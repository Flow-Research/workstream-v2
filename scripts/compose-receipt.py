"""Run inside the node container after all real services report ready."""
import json
from pathlib import Path
import socket
import ssl
import struct
import time


def rpc(method, params=None):
    with socket.create_connection(('127.0.0.1', 8545), timeout=3) as sock:
        sock.sendall(json.dumps(dict(id=1, jsonrpc='2.0', method=method, params=params)).encode() + b'\n')
        with sock.makefile('rb') as f:
            reply = json.loads(f.readline())
        if 'error' in reply:
            raise RuntimeError(f'{method}: {reply["error"]}')
        return reply['result']


def writer(request):
    ctx = ssl.create_default_context(cadata=Path('/identity/ca.der').read_bytes())
    ctx.load_cert_chain('/identity/cert.pem', '/identity/key.pem')
    with ctx.wrap_socket(socket.socket(socket.AF_UNIX), server_hostname='sequencer.workstream.internal') as sock:
        sock.settimeout(3)
        sock.connect('/ipc/runtime/writer.sock')
        data = json.dumps(request).encode()
        sock.sendall(struct.pack('!I', len(data)) + data)
        with sock.makefile('rb') as f:
            size, = struct.unpack('!I', f.read(4))
            assert 0 < size <= 16 << 20
            return json.loads(f.read(size))['Ok']


fixture = json.loads(Path('/app/signed-fixture.json').read_bytes())
genesis = rpc('workstream.node.verifiedTip')
assert genesis['height'] == 0, 'smoke requires a fresh chain'
ack = rpc('workstream.sequencer.submitTransaction', dict(version=1, api_version=1, tx_bytes=list(json.dumps(fixture).encode())))
assert ack['status'] == 'Pending'
deadline = time.monotonic() + 30
while (tip := rpc('workstream.node.verifiedTip'))['height'] == 0:
    if time.monotonic() >= deadline:
        raise TimeoutError(f'node stalled after admission; writer tip={writer("Tip")}')
    time.sleep(.1)
block = writer({'Block': 1})
assert block['transactions'] == [fixture] and block['header']['proof'] is not None
assert tip['height'] == 1 and tip['state_root'] != genesis['state_root']
assert tip['da_ref'] == block['header']['da_ref'] and any(tip['da_ref'])
assert writer('Tip') == [1, tip['state_root']]
print(json.dumps(dict(verified_height=1, tx_id=bytes(ack['tx_hash']).hex(), published_commitment=bytes(tip['da_ref']).hex(), verified_state_root=tip['state_root'])))
