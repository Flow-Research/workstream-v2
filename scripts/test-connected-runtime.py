"""Exercise signed admission, durable proving, independent application and outages."""
import contextlib
import glob
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time


def postgres_bin():
    patterns = ('/usr/lib/postgresql/*/bin', '/usr/local/opt/postgresql@*/bin',
                '/opt/homebrew/opt/postgresql@*/bin')
    for pattern in patterns:
        for candidate in sorted(glob.glob(pattern)):
            if all((Path(candidate) / tool).exists() for tool in ('initdb', 'pg_ctl', 'psql')):
                return Path(candidate)
    raise RuntimeError('PostgreSQL 16 server binaries are required for the proof-job drill')


def start_postgres(directory, cleanup):
    """Ephemeral socket-only cluster; no TCP listener, no reuse of developer state."""
    bindir = postgres_bin()
    data = directory / 'pgdata'
    sock = directory / 'pgsocket'
    data.mkdir(mode=0o700)
    sock.mkdir(mode=0o700)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        port = reserve.getsockname()[1]
    subprocess.run([bindir / 'initdb', '-D', str(data), '-A', 'trust',
                    '-U', 'postgres', '--no-instructions'],
                   check=True, capture_output=True)
    options = f"-k {sock} -c listen_addresses='' -p {port}"
    # pg_ctl's detached server inherits its stdout; capturing it would keep the
    # pipe open and hang. Keep a real log instead.
    log = (directory / 'postgres.log').open('wb')
    cleanup.callback(log.close)
    subprocess.run([bindir / 'pg_ctl', '-D', str(data), '-o', options,
                    '-w', '-t', '20', 'start'], check=True, stdout=log,
                   stderr=subprocess.STDOUT)
    cleanup.callback(lambda: subprocess.run(
        [bindir / 'pg_ctl', '-D', str(data), '-m', 'immediate', '-w', '-t', '20', 'stop'],
        stdout=log, stderr=subprocess.STDOUT))
    psql = [bindir / 'psql', '-h', str(sock), '-p', str(port), '-U', 'postgres',
            '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
    subprocess.run(psql + ['-c', 'CREATE ROLE worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE'],
                   check=True, capture_output=True)
    subprocess.run(psql + ['-c', 'CREATE DATABASE proofjobs'],
                   check=True, capture_output=True)
    proofjobs = psql + ['-d', 'proofjobs']
    subprocess.run(proofjobs + ['-c', 'GRANT CREATE, USAGE ON SCHEMA public TO worker'],
                   check=True, capture_output=True)
    subprocess.run(psql + ['-c', 'CREATE ROLE projection LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE'],
                   check=True, capture_output=True)
    subprocess.run(psql + ['-c', 'CREATE DATABASE projections'],
                   check=True, capture_output=True)
    projections = psql + ['-d', 'projections']
    subprocess.run(projections + ['-c', 'GRANT CREATE, USAGE ON SCHEMA public TO projection'],
                   check=True, capture_output=True)
    return sock, port, proofjobs


def wait(check):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except (ConnectionRefusedError, FileNotFoundError, subprocess.CalledProcessError):
            pass
        time.sleep(.05)
    raise TimeoutError('runtime did not reach expected state')


def run(directory, binaries, fixture, future_nonce):
    pki = directory / 'identities'
    subprocess.run(['bash', 'scripts/dev-service-identities.sh', pki], check=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith('WORKSTREAM_')}
    env['WORKSTREAM_RUNTIME_DIR'] = str(directory)

    data = directory / 'writer-data'
    data.mkdir(mode=0o700)
    env['WORKSTREAM_WRITER_DATA'] = str(data)
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

    def submit(transaction=fixture):
        return rpc('workstream.sequencer.submitTransaction', dict(version=1, api_version=1, tx_bytes=list(json.dumps(transaction).encode())))

    with contextlib.ExitStack() as cleanup:
        socket_dir, pg_port, psql = start_postgres(directory, cleanup)
        env['WORKSTREAM_JOBS_SOCKET'] = str(socket_dir)
        env['WORKSTREAM_JOBS_PORT'] = str(pg_port)

        def sql(query):
            return subprocess.check_output(psql + ['-At', '-c', query], text=True).strip()

        def start(role, extra=None):
            child_env = {'WORKSTREAM_IDENTITY_DIR': str(pki / role), **(extra or {})}
            child = subprocess.Popen([binaries / role], env={**env, **child_env})
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
        ack = submit()['result']
        assert ack['status'] == 'Pending'
        seq.kill()
        seq.wait()
        seq = start('sequencer')
        wait(lambda: writer('Tip') == [0, genesis['state_root']])
        assert submit()['result'] == ack
        receipt_method = 'workstream.node.getReceipt'
        lookup = {'tx_hash': ack['tx_hash']}
        assert rpc(receipt_method, lookup)['result']['status'] == 'Pending'
        queue = rpc('workstream.sequencer.getMempoolStatus')['result']
        assert queue['pending_count'] == 1 and queue['size_bytes'] > 0
        print(f'After SIGKILL: identical receipt, one pending transaction, {queue["size_bytes"]} signed bytes', flush=True)
        # Writer ticks twice with no worker. It must retain the pending action.
        time.sleep(1.25)
        assert writer('Tip')[0] == 0 and verified() == genesis
        print('Worker absent: signed admission pending, writer and verifier at height 0', flush=True)
        prover = start('prover', {'WORKSTREAM_DEV_PROOF_DELAY_MS': '5000'})
        wait(lambda: sql("SELECT count(*) FROM proof_job_witness") == '1')
        wait(lambda: sql("SELECT attempts FROM proof_job_status WHERE chain='1'") == '1')
        prover.kill()
        prover.wait()
        assert sql("SELECT count(*) FROM proof_job_witness") == '1'
        print('Worker SIGKILLed mid-proof: job and private witness retained', flush=True)
        start('prover')
        tip = wait(lambda: (t if (t := verified())['height'] == 1 else None))
        assert sql("SELECT count(*) FROM proof_job_witness") == '0'
        status = sql("SELECT attempts||','||(queue_ms IS NOT NULL)||','||(runtime_ms IS NOT NULL)||','||complete FROM proof_job_status WHERE chain='1'")
        assert status == '2,true,true,true', status
        assert sql("SELECT count(*) FROM information_schema.columns WHERE table_name='proof_job_status' AND column_name IN ('payload','result')") == '0'
        print(f'Worker restart reclaimed the job: {status}; status view has no witness bytes', flush=True)
        block = writer({'Block': 1})
        assert block['transactions'] == [fixture] and block['header']['proof'] is not None
        assert tip['state_root'] != genesis['state_root']
        assert writer('Tip') == [1, tip['state_root']]
        assert rpc(receipt_method,lookup)['result']['status'] == 'Verified'
        print('Signed action included; worker proof present; independent node matched writer:', json.dumps(tip), flush=True)
        seq.kill()
        seq.wait()
        assert 'error' in submit() and verified() == tip
        print('Writer stopped: admission failed, verified height unchanged', flush=True)
        start('sequencer')
        wait(lambda: writer('Tip') == [1, tip['state_root']])
        assert submit()['result']['status'] == 'Published'
        assert writer('Queue') == [0, 0]
        print('Published checkpoint restored; duplicate did not re-enter queue', flush=True)
        assert rpc(receipt_method, {'tx_hash': [0]*32})['result']['status'] == 'Unknown'
        invalid = submit(future_nonce)['result']
        wait(lambda: rpc(receipt_method, {'tx_hash': invalid['tx_hash']})['result']['status'] == 'Rejected')
        print('Unknown ID distinguished from durable semantic rejection', flush=True)


if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--quiet', '--bin', 'node', '--bin', 'sequencer', '--bin', 'prover'], check=True)
    fixture = json.loads(subprocess.check_output(['cargo','run','--quiet','-p','workstream-tests','--example','connected_fixture']))
    future_nonce = json.loads(subprocess.check_output(['cargo','run','--quiet','-p','workstream-tests','--example','connected_fixture','--','future-nonce']))
    target = json.loads(subprocess.check_output(['cargo','metadata','--format-version','1','--no-deps']))['target_directory']
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory), Path(target) / 'debug', fixture, future_nonce)
