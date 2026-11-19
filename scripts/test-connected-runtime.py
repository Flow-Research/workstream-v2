"""Exercise signed admission, remote proving, independent application and outages."""
import contextlib
import json
import os
from pathlib import Path
import socket
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

    def writer(req):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(3)
            sock.connect(str(directory / 'writer.sock'))
            data = json.dumps(req).encode()
            sock.sendall(struct.pack('!I', len(data)) + data)
            with sock.makefile('rb') as f:
                size, = struct.unpack('!I', f.read(4))
                return json.loads(f.read(size))['Ok']

    def verified():
        return rpc('workstream.node.verifiedTip')['result']

    def submit():
        return rpc('workstream.sequencer.submitTransaction', dict(version=1, api_version=1, tx_bytes=list(json.dumps(fixture).encode())))

    with contextlib.ExitStack() as cleanup:
        def start(role):
            child = subprocess.Popen([binaries / role], env=env)
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            return child

        seq = start('sequencer')
        start('node')
        genesis = wait(verified)
        wait(lambda: (directory / 'writer.sock').exists())
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
