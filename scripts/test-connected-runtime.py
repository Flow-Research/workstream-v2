"""Exercise signed admission, remote proving, independent application and outages."""
import contextlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time


def wait(check):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (ConnectionRefusedError, FileNotFoundError):
            pass
        time.sleep(.05)
    raise TimeoutError('runtime did not reach expected state')


def run(directory, binaries, fixture):
    pki = directory / 'identities'
    subprocess.run(['bash', 'scripts/dev-service-identities.sh', pki], check=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith('WORKSTREAM_')}
    env['WORKSTREAM_RUNTIME_DIR'] = str(directory)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    env['WORKSTREAM_NODE_RPC_PORT'] = str(port)

    def rpc(method, params=None):
        with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
            sock.sendall(json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode() + b'\n')
            return json.loads(sock.makefile('rb').readline())

    def writer(req, role='node'):
        ctx = ssl.create_default_context(cafile=str(pki / 'ca.pem'))
        if role:
            ctx.load_cert_chain(str(pki / role / 'cert.pem'), str(pki / role / 'key.pem'))
        with ctx.wrap_socket(socket.socket(socket.AF_UNIX), server_hostname='sequencer.workstream.internal') as sock:
            sock.settimeout(3)
            sock.connect(str(directory / 'writer.sock'))
            data = json.dumps(req).encode()
            sock.sendall(struct.pack('!I', len(data)) + data)
            with sock.makefile('rb') as f:
                header = f.read(4)
                if not header:
                    raise EOFError('service closed before dispatch')
                size, = struct.unpack('!I', header)
                return json.loads(f.read(size))['Ok']

    def verified():
        return rpc('workstream.node.verifiedTip')['result']

    def submit():
        return rpc('workstream.sequencer.submitTransaction', dict(version=1, api_version=1, tx_bytes=list(json.dumps(fixture).encode())))

    with contextlib.ExitStack() as cleanup:
        def start(role):
            child = subprocess.Popen([binaries / role], env={**env, 'WORKSTREAM_IDENTITY_DIR': str(pki / role)})
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            return child

        seq = start('sequencer')
        start('node')
        genesis = wait(verified)
        wait(lambda: (directory / 'writer.sock').exists())
        for role in (None, 'prover'):
            try:
                writer('Tip', role)
            except (EOFError, ssl.SSLError, ConnectionResetError, BrokenPipeError):
                print(f'Writer rejected caller: {role or "no client certificate"}', flush=True)
            else:
                raise AssertionError('unauthorized caller received a writer response')
        assert rpc('workstream.prover.proveBlock')['error']['code'] == -32601
        with socket.create_connection(('127.0.0.1', port), timeout=3) as malformed:
            malformed.sendall(b'{not-json}\n')
            assert json.loads(malformed.makefile('rb').readline())['error']['code'] == -32700
        with socket.create_connection(('127.0.0.1', port), timeout=3) as interrupted:
            interrupted.sendall(b'{')
        assert submit()['result']['status'] == 'Pending'
        # Writer ticks twice with no worker. It must retain the pending action.
        time.sleep(1.25)
        assert writer('Tip')[0] == 0 and verified() == genesis
        print('Worker absent: signed admission pending, writer and verifier at height 0', flush=True)
        start('prover')
        tip = wait(lambda: (t if (t := verified())['height'] == 1 else None))
        block = writer({'Block': 1})
        assert block['transactions'] == [fixture] and block['header']['proof'] is not None
        assert tip['state_root'] != genesis['state_root']
        assert writer('Tip') == [1, tip['state_root']]
        print('Signed action included; worker proof present; independent node matched writer:', json.dumps(tip), flush=True)
        seq.kill()
        seq.wait()
        assert 'error' in submit() and verified() == tip
        print('Writer stopped: admission failed, verified height unchanged', flush=True)


if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--quiet', '--bin', 'node', '--bin', 'sequencer', '--bin', 'prover'], check=True)
    fixture = json.loads(subprocess.check_output(['cargo','run','--quiet','-p','workstream-tests','--example','connected_fixture']))
    target = json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps']))['target_directory']
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory), Path(target) / 'debug', fixture)
