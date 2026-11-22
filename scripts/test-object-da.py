"""Process drill for S3-compatible DA: independent fetch, outage, restore."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import time


def load_connected():
    path = Path(__file__).with_name('test-connected-runtime.py')
    spec = importlib.util.spec_from_file_location('connected_runtime', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


connected = load_connected()


def wait(check, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (ConnectionRefusedError, FileNotFoundError, KeyError, OSError,
                ssl.SSLError, subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(.1)
    raise TimeoutError('object DA drill did not reach expected state')


def run(directory, binaries, first, second):
    pki = directory / 'identities'
    subprocess.run(['bash', 'scripts/dev-service-identities.sh', pki], check=True)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        s3_port = reserve.getsockname()[1]
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        rpc_port = reserve.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('WORKSTREAM_')}
    env.update({
        'WORKSTREAM_RUNTIME_DIR': str(directory),
        'WORKSTREAM_NODE_RPC_PORT': str(rpc_port),
        'WORKSTREAM_DA_ENDPOINT': f'http://127.0.0.1:{s3_port}',
        'WORKSTREAM_DA_BUCKET': 'workstream',
        'WORKSTREAM_DA_PREFIX': 'workstream',
        'WORKSTREAM_DA_ACCESS_KEY': 'test-key',
        'WORKSTREAM_DA_SECRET_KEY': 'test-secret',
    })
    data = directory / 'writer-data'
    data.mkdir(mode=0o700)
    env['WORKSTREAM_WRITER_DATA'] = str(data)
    db = directory / 'mock-s3.json'

    def rpc(method, params=None):
        with socket.create_connection(('127.0.0.1', rpc_port), timeout=3) as sock:
            sock.sendall(json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode() + b'\n')
            return json.loads(sock.makefile('rb').readline())

    def writer(request, role='node'):
        ctx = ssl.create_default_context(cafile=str(pki / 'ca.pem'))
        ctx.load_cert_chain(str(pki / role / 'cert.pem'), str(pki / role / 'key.pem'))
        with ctx.wrap_socket(socket.socket(socket.AF_UNIX),
                             server_hostname='sequencer.workstream.internal') as sock:
            sock.settimeout(3)
            sock.connect(str(directory / 'writer.sock'))
            payload = json.dumps(request).encode()
            sock.sendall(struct.pack('!I', len(payload)) + payload)
            with sock.makefile('rb') as stream:
                header = stream.read(4)
                if not header:
                    raise EOFError('writer closed before dispatch')
                size, = struct.unpack('!I', header)
                return json.loads(stream.read(size))['Ok']

    def verified():
        return rpc('workstream.node.verifiedTip')['result']

    def port_open():
        try:
            with socket.create_connection(('127.0.0.1', s3_port), timeout=.2):
                return True
        except OSError:
            return False

    with contextlib.ExitStack() as cleanup:
        sock_dir, pg_port, _ = connected.start_postgres(directory, cleanup)
        env['WORKSTREAM_JOBS_SOCKET'] = str(sock_dir)
        env['WORKSTREAM_JOBS_PORT'] = str(pg_port)

        def start_mock():
            log = (directory / 'mock-s3.log').open('ab')
            cleanup.callback(log.close)
            child = subprocess.Popen(
                [sys.executable, 'scripts/mock-s3.py', str(s3_port), str(db)],
                env={**env,
                     'MOCK_S3_ACCESS_KEY': env['WORKSTREAM_DA_ACCESS_KEY'],
                     'MOCK_S3_SECRET_KEY': env['WORKSTREAM_DA_SECRET_KEY']},
                stdout=log, stderr=subprocess.STDOUT)
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            wait(port_open)
            return child

        def start(role):
            child_env = {'WORKSTREAM_IDENTITY_DIR': str(pki / role)}
            child = subprocess.Popen([binaries / role], env={**env, **child_env})
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            return child

        mock = start_mock()
        start('sequencer')
        start('prover')
        wait(lambda: writer('Tip')[0] == 0)
        ack = writer({'Submit': first})
        assert ack['status'] == 'Pending', ack
        wait(lambda: writer('Tip')[0] == 1)
        block = writer({'Block': 1})
        assert block['transactions'] == [first] and block['header']['proof'] is not None
        objects = json.loads(db.read_text())
        assert len(objects) == 1 and all('/blocks/' in key for key in objects), objects
        print(f'Published block 1 to provider: {len(objects)} signed and verified object', flush=True)

        # Remove producer-local block bytes. The node must still be able to
        # fetch the exact published bytes using only the DA reference.
        with sqlite3.connect(data / 'chain-1.sqlite') as journal:
            journal.execute('DELETE FROM blocks WHERE height=1')
        assert writer({'Block': 1}) is None
        reference = writer({'DaRef': 1})
        assert reference[0] == 1 and len(reference[1]) == 32, reference
        print('Producer-local block bytes removed; journal exposes only the DA reference', flush=True)

        start('node')
        tip = wait(lambda: (value if (value := verified())['height'] == 1 else None))
        assert tip['da_ref'] == reference[1], (tip, reference)
        print('Independent node fetched and verified DA bytes without producer-local state', flush=True)

        mock.kill()
        mock.wait()
        wait(lambda: not port_open())
        ack2 = writer({'Submit': second})
        assert ack2['status'] == 'Pending', ack2
        time.sleep(2)
        assert writer('Tip')[0] == 1, writer('Tip')
        assert verified() == tip
        print('Provider unavailable: publication deferred, verified tip unchanged', flush=True)

        start_mock()
        tip2 = wait(lambda: (value if (value := verified())['height'] == 2 else None))
        assert writer('Tip')[0] == 2
        assert tip2['da_ref'] != tip['da_ref']
        objects = json.loads(db.read_text())
        assert len(objects) == 2 and all('/blocks/' in key for key in objects), objects
        print(f'Provider restored from its own store: block 2 verified, {len(objects)} retained objects', flush=True)


if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--quiet', '--bin', 'node', '--bin', 'sequencer', '--bin', 'prover'],
                   check=True)
    first = json.loads(subprocess.check_output(
        ['cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example', 'connected_fixture']))
    second = json.loads(subprocess.check_output(
        ['cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example', 'connected_fixture', '--', 'nonce=1']))
    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps']))['target_directory']
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory), Path(target) / 'debug', first, second)
