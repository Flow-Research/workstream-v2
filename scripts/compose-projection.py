"""Run inside the node container to assert live projection status and reads."""
import json
import socket


def rpc(method, params=None):
    with socket.create_connection(('127.0.0.1', 8545), timeout=3) as sock:
        sock.sendall(json.dumps(dict(id=1, jsonrpc='2.0', method=method, params=params)).encode() + b'\n')
        with sock.makefile('rb') as f:
            reply = json.loads(f.readline())
        if 'error' in reply:
            raise RuntimeError(f'{method}: {reply["error"]}')
        return reply['result']


status = rpc('workstream.indexer.getStatus')
assert status['verified_height'] == 1, status
assert status['indexed_height'] == 1, status
assert status['lag'] == 0, status
assert status['schema_version'] == 1, status

receipts = rpc('workstream.indexer.getPage', dict(kind='receipts', limit=10))
assert len(receipts['items']) == 1, receipts
assert receipts['next_cursor'] is None, receipts
events = rpc('workstream.indexer.getPage', dict(kind='events', limit=10))
assert len(events['items']) >= 1, events
assert events['items'][0]['event_type'] == 'actor.registered', events
print(json.dumps(dict(
    verified_height=status['verified_height'],
    indexed_height=status['indexed_height'],
    lag=status['lag'],
    receipts=len(receipts['items']),
    events=len(events['items']),
)))
