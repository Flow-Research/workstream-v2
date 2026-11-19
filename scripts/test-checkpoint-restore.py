"""Crash-window drill for stable publication keys and verified checkpoint restore."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import time


def load_module(name, filename):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


connected = load_module('connected_runtime', 'test-connected-runtime.py')


def wait(check, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (ConnectionRefusedError, EOFError, FileNotFoundError, KeyError,
                OSError, ssl.SSLError, subprocess.CalledProcessError,
                json.JSONDecodeError, sqlite3.OperationalError):
            pass
        time.sleep(.1)
    raise TimeoutError('checkpoint restore drill did not reach expected state')


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def decode_varint(raw, offset):
    result = 0
    shift = 0
    while True:
        byte = raw[offset]
        offset += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def envelope_payload(raw):
    version, offset = decode_varint(raw, 0)
    assert version == 1, version
    digest = raw[offset:offset + 32]
    offset += 32
    length, offset = decode_varint(raw, offset)
    payload = raw[offset:offset + length]
    assert len(payload) == length and hashlib.sha256(payload).digest() == digest
    return payload


def export_archive(db_path, archive):
    archive.mkdir()
    objects = json.loads(Path(db_path).read_text())
    blocks = []
    for key, encoded in objects.items():
        if '/blocks/' not in key:
            continue
        payload = envelope_payload(__import__('base64').b64decode(encoded))
        block = json.loads(payload)
        height = block['header']['number']
        (archive / f'{height:08d}.json').write_bytes(payload)
        blocks.append({'height': height,
                       'da_ref': list(bytes.fromhex(key.rsplit('/', 1)[1]))})
    blocks.sort(key=lambda entry: entry['height'])
    assert [entry['height'] for entry in blocks] == list(range(1, len(blocks) + 1))
    (archive / 'manifest.json').write_text(json.dumps({'version': 1, 'blocks': blocks}))
    return len(blocks)


def run(directory, binaries, fixtures):
    pki = directory / 'identities'
    subprocess.run(['bash', 'scripts/dev-service-identities.sh', pki], check=True,
                   stdout=subprocess.DEVNULL)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        s3_port = reserve.getsockname()[1]
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        rpc_port = reserve.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('WORKSTREAM_')}
    env.update({
        'WORKSTREAM_PROFILE': 'dev',
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
    processes = {}

    def rpc(method, params=None):
        with socket.create_connection(('127.0.0.1', rpc_port), timeout=3) as sock:
            sock.sendall(json.dumps(dict(jsonrpc='2.0', id=1, method=method,
                                         params=params)).encode() + b'\n')
            return json.loads(sock.makefile('rb').readline())

    def verified():
        reply = rpc('workstream.node.verifiedTip')
        assert 'error' not in reply, reply
        return reply['result']

    def submit(tx):
        return rpc('workstream.sequencer.submitTransaction',
                   {'version': 1, 'api_version': 1,
                    'tx_bytes': list(json.dumps(tx).encode())})

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
                size, = struct.unpack('!I', stream.read(4))
                return json.loads(stream.read(size))['Ok']

    def objects():
        return json.loads(db.read_text()) if db.exists() else {}

    def publication(height):
        with sqlite3.connect(data / 'chain-1.sqlite') as journal:
            return journal.execute(
                'SELECT hex(da_ref),accepted FROM publications WHERE height=?', (height,)
            ).fetchone()

    def pending_admissions():
        with sqlite3.connect(data / 'chain-1.sqlite') as journal:
            return journal.execute(
                "SELECT count(*) FROM admissions WHERE status='Pending'"
            ).fetchone()[0]

    def checkpoint_height():
        with sqlite3.connect(data / 'chain-1.sqlite') as journal:
            return journal.execute(
                'SELECT height FROM checkpoint_meta WHERE id=1'
            ).fetchone()[0]

    def sql(query):
        return subprocess.check_output(psql + ['-At', '-c', query], text=True).strip()

    with contextlib.ExitStack() as cleanup:
        sock_dir, pg_port, psql = connected.start_postgres(directory, cleanup)
        env['WORKSTREAM_JOBS_SOCKET'] = str(sock_dir)
        env['WORKSTREAM_JOBS_PORT'] = str(pg_port)

        def port_open():
            try:
                with socket.create_connection(('127.0.0.1', s3_port), timeout=.2):
                    return True
            except OSError:
                return False

        def start_mock():
            log = (directory / 'mock-s3.log').open('ab')
            cleanup.callback(log.close)
            child = subprocess.Popen(
                [sys.executable, 'scripts/mock-s3.py', str(s3_port), str(db)],
                env={**env, 'MOCK_S3_ACCESS_KEY': 'test-key',
                     'MOCK_S3_SECRET_KEY': 'test-secret'},
                stdout=log, stderr=subprocess.STDOUT, preexec_fn=no_core)
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            wait(port_open)
            return child

        def start(role, crash=None):
            child_env = {'WORKSTREAM_IDENTITY_DIR': str(pki / role)}
            if crash:
                child_env['WORKSTREAM_DEV_CRASH_STAGE'] = crash
            child = subprocess.Popen([binaries / role], env={**env, **child_env},
                                     preexec_fn=no_core)
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            processes[role] = child
            return child

        def stop(role):
            child = processes.pop(role, None)
            if child is not None and child.poll() is None:
                child.kill()
            if child is not None:
                child.wait()

        start_mock()
        start('sequencer', 'admission')
        start('prover')
        start('node')
        genesis = wait(verified)
        wait(lambda: writer('Tip')[0] == 0)
        print(f'Genesis verifier root: {genesis["state_root"]["smt_root"][:8]}', flush=True)

        # 1. Crash after the signed admission is durable but before acknowledgement.
        try:
            submit(fixtures[0])
        except (OSError, json.JSONDecodeError):
            pass
        wait(lambda: processes['sequencer'].poll() is not None)
        assert pending_admissions() == 1 and publication(1) is None
        print('Admission crash: signed bytes durable, no publication recorded', flush=True)
        stop('sequencer')
        start('sequencer')
        tip1 = wait(lambda: (t if (t := verified())['height'] == 1 else None))
        assert publication(1)[1] == 1
        assert len(objects()) == 1
        print(f'Admission replay: one canonical block at height 1, DA key {list(objects())[0].rsplit("/",1)[1][:8]}', flush=True)

        # 2. Crash after durable proof completion but before the writer receives it.
        stop('prover')
        start('prover', 'proof-completed')
        ack2 = submit(fixtures[1])['result']
        assert ack2['status'] == 'Pending'
        wait(lambda: processes['prover'].poll() is not None)
        assert sql("SELECT count(*) FROM proof_job_witness") == '0'
        assert sql("SELECT count(*) FROM proof_job_status WHERE complete") == '2'
        assert verified() == tip1 and writer('Tip')[0] == 1
        print('Proof-completion crash: keyed result durable, writer tip unchanged', flush=True)
        stop('prover')
        start('prover')
        tip2 = wait(lambda: (t if (t := verified())['height'] == 2 else None))
        assert len(objects()) == 2 and publication(2)[1] == 1
        print('Proof replay: stored keyed proof reused, no duplicate publication', flush=True)

        # 3. Crash after DA acceptance but before the local checkpoint commit.
        stop('sequencer')
        start('sequencer', 'da-accepted')
        wait(lambda: writer('Tip')[0] == 2)
        ack3 = submit(fixtures[2])['result']
        assert ack3['status'] == 'Pending'
        wait(lambda: processes['sequencer'].poll() is not None)
        assert publication(3)[1] == 0 and checkpoint_height() == 2
        before = dict(objects())
        # The stored key is hex bytes of the DA reference; locate it directly.
        key3 = next(key for key in before if key.rsplit('/', 1)[1] ==
                    bytes.fromhex(publication(3)[0]).hex())
        print(f'DA-acceptance crash: object stored under stable key {key3.rsplit("/",1)[1][:8]}, local tip still 2', flush=True)
        stop('sequencer')
        start('sequencer')
        tip3 = wait(lambda: (t if (t := verified())['height'] == 3 else None))
        assert objects() == before and publication(3)[1] == 1
        print('DA replay: identical key and bytes, only the local checkpoint advanced', flush=True)

        # 4. Crash after the local checkpoint commit.
        stop('sequencer')
        start('sequencer', 'local-commit')
        wait(lambda: writer('Tip')[0] == 3)
        wait(lambda: verified()['height'] == 3)
        ack4 = submit(fixtures[3])['result']
        assert ack4['status'] == 'Pending'
        wait(lambda: processes['sequencer'].poll() is not None)
        assert publication(4)[1] == 1 and checkpoint_height() == 4
        print('Local-commit crash: publication and checkpoint both durable', flush=True)
        stop('sequencer')
        start('sequencer')
        tip4 = wait(lambda: (t if (t := verified())['height'] == 4 else None))
        assert writer('Tip') == [4, tip4['state_root']] and writer('Queue') == [0, 0]
        assert len(objects()) == 4 and publication(4)[1] == 1
        assert len({bytes.fromhex(publication(h)[0]) for h in range(1, 5)}) == 4
        print(f'Commit replay: one canonical outcome, tip {tip4["height"]}, state root {tip4["state_root"]["smt_root"][:8]}', flush=True)

        # Restore a fresh verifier from the archive plus an external checkpoint.
        archive = directory / 'archive'
        count = export_archive(db, archive)
        checkpoint = archive.parent / 'trusted-checkpoint.json'
        trusted = {'height': tip4['height'], 'state_root': tip4['state_root'],
                   'da_ref': tip4['da_ref']}
        checkpoint.write_text(json.dumps(trusted))
        restored_state = directory / 'restored-state'
        result = subprocess.run(
            [binaries / 'workstream-restore', '--archive', str(archive),
             '--checkpoint', str(checkpoint), '--out', str(restored_state)],
            capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(f'restore failed: {result.stderr}')
        restored = json.loads(result.stdout)
        assert restored['height'] == tip4['height']
        assert restored['state_root'] == tip4['state_root']
        assert restored['da_ref'] == tip4['da_ref']
        assert (restored_state / 'state.json').exists()
        print(f'Fresh restore: {count} archived blocks verified from genesis; tip and state root match trusted checkpoint', flush=True)

        # A tampered checkpoint must be rejected, not silently accepted.
        bad = dict(trusted)
        bad['state_root'] = dict(trusted['state_root'])
        bad['state_root']['smt_root'] = [0] * 32
        (archive.parent / 'bad-checkpoint.json').write_text(json.dumps(bad))
        denied = subprocess.run(
            [binaries / 'workstream-restore', '--archive', str(archive),
             '--checkpoint', str(archive.parent / 'bad-checkpoint.json')],
            capture_output=True, text=True)
        assert denied.returncode != 0 and 'disagrees with trusted checkpoint' in denied.stderr
        print('Checkpoint trust policy: mismatched checkpoint rejected after full archive verification', flush=True)


if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--quiet', '--bin', 'node', '--bin', 'sequencer',
                    '--bin', 'prover', '--bin', 'workstream-restore'], check=True)
    fixtures = []
    for nonce in range(4):
        fixtures.append(json.loads(subprocess.check_output(
            ['cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example',
             'connected_fixture', '--', f'nonce={nonce}'])))
    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps']))['target_directory']
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory), Path(target) / 'debug', fixtures)
