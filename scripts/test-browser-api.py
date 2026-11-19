"""Browser-safe HTTPS API drill: TLS 1.3, sessions, idempotency, CORS, stale views.

Starts the connected runtime with the browser API enabled, then drives it over
a real rustls TLS listener with a trusted dev CA. Asserts stable error codes,
request-id idempotency, exact-origin CORS, security headers, and that no
signing key, witness or private field crosses the boundary.
"""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


connected = load_module('connected_runtime', 'test-connected-runtime.py')


def reserve():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait(check, seconds=25):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (ConnectionRefusedError, EOFError, FileNotFoundError, KeyError,
                OSError, ssl.SSLError, subprocess.CalledProcessError,
                json.JSONDecodeError):
            pass
        time.sleep(.1)
    raise TimeoutError('browser API drill did not reach expected state')


def request(port, cafile, method, path, body=None, headers=None):
    """One HTTPS/1.1 request; returns (status, headers, parsed JSON body)."""
    context = ssl.create_default_context(cafile=str(cafile))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with context.wrap_socket(
        socket.create_connection(('127.0.0.1', port), timeout=4),
        server_hostname='node.workstream.internal',
    ) as sock:
        lines = [f'{method} {path} HTTP/1.1', 'Host: node.workstream.internal',
                 'Connection: close']
        for key, value in (headers or {}).items():
            lines.append(f'{key}: {value}')
        payload = b''
        if body is not None:
            payload = json.dumps(body).encode()
            lines.append(f'Content-Length: {len(payload)}')
            lines.append('Content-Type: application/json')
        sock.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode() + payload)
        raw = b''
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
    head, _, response_body = raw.partition(b'\r\n\r\n')
    status = int(head.split(b'\r\n')[0].split()[1])
    response_headers = {}
    for line in head.split(b'\r\n')[1:]:
        if b':' in line:
            key, _, value = line.partition(b':')
            response_headers[key.decode().lower()] = value.strip().decode()
    parsed = json.loads(response_body) if response_body.strip() else None
    return status, response_headers, parsed


def run(directory, binaries, fixture):
    pki = directory / 'identities'
    subprocess.run(['bash', 'scripts/dev-service-identities.sh', pki], check=True,
                   stdout=subprocess.DEVNULL)
    env = {k: v for k, v in os.environ.items() if not k.startswith('WORKSTREAM_')}
    env['WORKSTREAM_RUNTIME_DIR'] = str(directory)
    env['WORKSTREAM_WRITER_DATA'] = str(directory / 'data')
    (directory / 'data').mkdir(mode=0o700)
    rpc_port, api_port = reserve(), reserve()
    env['WORKSTREAM_NODE_RPC_PORT'] = str(rpc_port)
    env['WORKSTREAM_API_PORT'] = str(api_port)
    env['WORKSTREAM_API_ORIGINS'] = 'https://app.example'
    env['WORKSTREAM_API_BIND'] = '127.0.0.1'

    def rpc(method, params=None):
        with socket.create_connection(('127.0.0.1', rpc_port), timeout=3) as sock:
            sock.sendall(json.dumps(dict(jsonrpc='2.0', id=1, method=method,
                                         params=params)).encode() + b'\n')
            return json.loads(sock.makefile('rb').readline())

    with contextlib.ExitStack() as cleanup:
        socket_dir, pg_port, _ = connected.start_postgres(directory, cleanup)
        env['WORKSTREAM_JOBS_SOCKET'] = str(socket_dir)
        env['WORKSTREAM_JOBS_PORT'] = str(pg_port)
        env['WORKSTREAM_PROJECTIONS_SOCKET'] = str(socket_dir)
        env['WORKSTREAM_PROJECTIONS_PORT'] = str(pg_port)

        def start(role, extra=None):
            child_env = {'WORKSTREAM_IDENTITY_DIR': str(pki / role), **(extra or {})}
            child = subprocess.Popen([binaries / role], env={**env, **child_env})
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            return child

        start('sequencer')
        start('node')
        wait(lambda: rpc('workstream.node.verifiedTip')['result'])
        ca = pki / 'ca.pem'

        # API requires an unexpired session; rejected before any data is read.
        status, headers, body = request(api_port, ca, 'GET', '/v1/chain')
        assert status == 401, (status, body)
        assert body['error']['code'] == 'UNAUTHORIZED'
        assert body['api_version'] == 1 and body['request_id']
        assert headers['x-content-type-options'] == 'nosniff'
        assert headers['cache-control'] == 'no-store'
        print('TLS 1.3 handshake and security headers; data route fails closed without session', flush=True)

        # CORS: exact allowlist, no wildcard, no credentials.
        status, headers, _ = request(api_port, ca, 'OPTIONS', '/v1/chain',
                                    headers={'Origin': 'https://app.example'})
        assert status == 204, status
        assert headers['access-control-allow-origin'] == 'https://app.example'
        assert 'access-control-allow-credentials' not in headers
        status, _, _ = request(api_port, ca, 'OPTIONS', '/v1/chain',
                              headers={'Origin': 'https://evil.example'})
        assert status == 403, status
        print('CORS exact-origin allowlist; no wildcard origin and no credentials', flush=True)

        status, _, body = request(api_port, ca, 'POST', '/v1/session',
                                  body={}, headers={'X-Request-Id': 's1'})
        assert status == 200, (status, body)
        token = body['data']['token']
        assert body['data']['api_version'] == 1
        auth = {'Authorization': f'Bearer {token}'}

        status, _, body = request(api_port, ca, 'GET', '/v1/chain',
                                  headers={**auth, 'X-Request-Id': 'c1'})
        assert status == 200, (status, body)
        chain = body['data']
        assert body['network'] == '1' and body['read_height'] >= 0
        assert 'state_root' in chain and 'stale' in chain
        assert 'witness' not in json.dumps(body) and 'private_key' not in json.dumps(body)
        print(f'Session, chain status and envelope: network={body["network"]}, height={body["read_height"]}', flush=True)

        # Submission reuses protocol validation: unsigned bytes are rejected
        # with a stable code, never forwarded to the writer.
        bad_tx = dict(fixture)
        bad_tx['signature'] = None
        submit_body = {'version': 1, 'api_version': 1,
                       'tx_bytes': list(json.dumps(bad_tx).encode())}
        status, _, body = request(api_port, ca, 'POST', '/v1/submit',
                                  body=submit_body,
                                  headers={**auth, 'X-Request-Id': 'bad-1'})
        assert status == 400, (status, body)
        assert body['error']['code'] == 'INVALID_TRANSACTION'

        good_submit = {'version': 1, 'api_version': 1,
                       'tx_bytes': list(json.dumps(fixture).encode())}
        headers = {**auth, 'X-Request-Id': 'sub-1'}
        status, _, first = request(api_port, ca, 'POST', '/v1/submit',
                                   body=good_submit, headers=headers)
        assert status == 200, (status, first)
        status, _, replay = request(api_port, ca, 'POST', '/v1/submit',
                                    body=good_submit, headers=headers)
        assert status == 200 and replay == first
        changed = dict(good_submit, tx_bytes=list(json.dumps(bad_tx).encode()))
        status, _, body = request(api_port, ca, 'POST', '/v1/submit',
                                  body=changed, headers=headers)
        assert status == 409 and body['error']['code'] == 'DUPLICATE_REQUEST'
        print('Protocol validation and request-id idempotency: unsigned rejected, replay cached, reuse conflict', flush=True)

        status, _, body = request(api_port, ca, 'GET', '/v1/tasks?limit=5',
                                  headers={**auth, 'X-Request-Id': 't1'})
        assert status == 200, (status, body)
        assert body['data']['kind'] == 'work_items' and 'stale' in body['data']
        status, _, body = request(api_port, ca, 'GET', '/v1/openapi.json')
        assert status == 200 and body['openapi'] == '3.1.0'
        assert '/v1/submit' in body['paths'] and '/v1/tasks' in body['paths']
        print('Projection read model and OpenAPI document served over the browser API', flush=True)


if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--quiet', '--bin', 'node', '--bin', 'sequencer',
                    '--bin', 'prover'], check=True)
    fixture = json.loads(subprocess.check_output(
        ['cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example', 'connected_fixture']))
    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps']))['target_directory']
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory), Path(target) / 'debug', fixture)
