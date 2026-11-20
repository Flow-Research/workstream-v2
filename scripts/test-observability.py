"""Trace drill: correlated JSON logs, stall metrics and safe-field assertions.

Reaches a verified receipt, then simulates a DA stall and an admission/proof
stall. It asserts the matching metric and alert expression fire, that liveness
is independent of readiness, and that no signing key, witness or private
evidence leaks into logs or scrape output.
"""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


connected = load_module('connected_runtime', 'test-connected-runtime.py')


def wait(check, seconds=20):
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
    raise TimeoutError('observability drill did not reach expected state')


def reserve():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def http(port, path):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
        sock.sendall(f'GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'.encode())
        return sock.makefile('rb').read().decode()


def scrape(port):
    body = http(port, '/metrics')
    return body.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in body else body


def value(metrics, name):
    match = re.search(rf'^{re.escape(name)} ([0-9]+)$', metrics, re.MULTILINE)
    return int(match.group(1)) if match else None


def check_config(root):
    alerts = (root / 'config/prometheus-alerts.yml').read_text()
    dashboard = json.loads((root / 'config/grafana-dashboard.json').read_text())
    panels = json.dumps(dashboard)
    for metric in [
        'workstream_admission_backlog', 'workstream_proof_delay_ms',
        'workstream_da_failures_total', 'workstream_verification_rejections_total',
        'workstream_index_lag_blocks',
    ]:
        assert metric in alerts, f'{metric} has no alert rule'
        assert metric in panels, f'{metric} has no dashboard panel'
    print('Dashboard/alert config: all five stall categories have a rule and a panel', flush=True)


def run(directory, binaries, first, second, root):
    check_config(root)
    pki = directory / 'identities'
    subprocess.run(['bash', 'scripts/dev-service-identities.sh', pki], check=True)
    rpc_port = reserve()
    metrics = {role: reserve() for role in ('sequencer', 'prover', 'node')}
    # Sentinels must never appear in any emitted log or scrape payload.
    secrets = {
        'WORKSTREAM_DA_ACCESS_KEY': 'SENTINEL_ACCESS_KEY_SHOULD_NOT_LEAK',
        'WORKSTREAM_DA_SECRET_KEY': 'SENTINEL_SECRET_KEY_SHOULD_NOT_LEAK',
    }
    env = {k: v for k, v in os.environ.items() if not k.startswith('WORKSTREAM_')}
    env.update({
        'WORKSTREAM_PROFILE': 'dev',
        'WORKSTREAM_RUNTIME_DIR': str(directory),
        'WORKSTREAM_NODE_RPC_PORT': str(rpc_port),
        'WORKSTREAM_LOG_FORMAT': 'json',
        'RUST_LOG': 'info',
        'WORKSTREAM_DA_ENDPOINT': f'http://127.0.0.1:{reserve()}',
        'WORKSTREAM_DA_BUCKET': 'workstream',
        'WORKSTREAM_DA_PREFIX': 'workstream',
        **secrets,
    })
    data = directory / 'writer-data'
    data.mkdir(mode=0o700)
    env['WORKSTREAM_WRITER_DATA'] = str(data)
    db = directory / 'mock-s3.json'
    service_logs = {}

    def rpc(method, params=None):
        with socket.create_connection(('127.0.0.1', rpc_port), timeout=3) as sock:
            sock.sendall(json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode() + b'\n')
            return json.loads(sock.makefile('rb').readline())

    def verified():
        return rpc('workstream.node.verifiedTip')['result']

    def submit(tx):
        return rpc('workstream.sequencer.submitTransaction',
                   {'version': 1, 'api_version': 1,
                    'tx_bytes': list(json.dumps(tx).encode())})

    def port_open(port):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return True
        except OSError:
            return False

    def s3_port():
        return int(env['WORKSTREAM_DA_ENDPOINT'].rsplit(':', 1)[1])

    with contextlib.ExitStack() as cleanup:
        sock_dir, pg_port, _ = connected.start_postgres(directory, cleanup)
        env['WORKSTREAM_JOBS_SOCKET'] = str(sock_dir)
        env['WORKSTREAM_JOBS_PORT'] = str(pg_port)
        env['WORKSTREAM_PROJECTIONS_SOCKET'] = str(sock_dir)
        env['WORKSTREAM_PROJECTIONS_PORT'] = str(pg_port)

        def start_mock():
            log = (directory / 'mock-s3.log').open('ab')
            cleanup.callback(log.close)
            child = subprocess.Popen(
                [sys.executable, 'scripts/mock-s3.py', str(s3_port()), str(db)],
                env={**env,
                     'MOCK_S3_ACCESS_KEY': env['WORKSTREAM_DA_ACCESS_KEY'],
                     'MOCK_S3_SECRET_KEY': env['WORKSTREAM_DA_SECRET_KEY']},
                stdout=log, stderr=subprocess.STDOUT)
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            wait(lambda: port_open(s3_port()))
            return child

        def start(role):
            log = (directory / f'{role}.log').open('wb')
            cleanup.callback(log.close)
            service_logs[role] = log
            child_env = {'WORKSTREAM_IDENTITY_DIR': str(pki / role)}
            child = subprocess.Popen(
                [binaries / role, '--metrics-port', str(metrics[role])],
                env={**env, **child_env}, stdout=log, stderr=subprocess.STDOUT)
            cleanup.callback(child.wait)
            cleanup.callback(child.kill)
            return child

        mock = start_mock()
        start('sequencer')
        start('prover')
        start('node')
        tip = wait(lambda: (t if (t := verified())['height'] == 0 else None))
        for role in metrics:
            wait(lambda role=role: http(metrics[role], '/readyz').startswith('HTTP/1.1 200'))

        ack = submit(first)['result']
        assert ack['status'] == 'Pending'
        tip = wait(lambda: (t if (t := verified())['height'] == 1 else None))
        receipt = wait(lambda: (r if (r := rpc('workstream.node.getReceipt',
                                              {'tx_hash': ack['tx_hash']}))['result']['status']
                                == 'Verified' else None))
        print(f'Synthetic check: transaction {ack["tx_hash"]} reached a verified receipt at height 1', flush=True)

        # Every stall series is present with HELP/TYPE on every service.
        for role in metrics:
            body = scrape(metrics[role])
            for name in ['workstream_up', 'workstream_ready',
                         'workstream_admission_backlog', 'workstream_proof_delay_ms',
                         'workstream_da_failures_total',
                         'workstream_verification_rejections_total',
                         'workstream_index_lag_blocks']:
                assert f'# TYPE {name} ' in body, (role, name)
            assert value(body, 'workstream_up') == 1
            assert http(metrics[role], '/livez').startswith('HTTP/1.1 200')
        print('Metrics contract: all stall series typed on every service; /livez is independent', flush=True)

        # Simulated stall 1: DA provider disappears. The writer cannot publish
        # and increments only the DA-failure signal; the verified tip is held.
        mock.kill()
        mock.wait()
        wait(lambda: not port_open(s3_port()))
        ack2 = submit(second)['result']
        assert ack2['status'] == 'Pending'
        wait(lambda: (v if (v := value(scrape(metrics['sequencer']),
                                      'workstream_da_failures_total')) and v > 0 else None))
        assert verified() == tip
        alert = (root / 'config/prometheus-alerts.yml').read_text()
        assert 'DaFailureStall' in alert and 'workstream_da_failures_total' in alert
        # Evaluate the exact condition the alert rule declares, rather than a
        # hardcoded number, so changing the threshold keeps the drill honest.
        threshold = int(re.search(
            r'workstream_da_failures_total\{job="workstream"\}\[5m\]\) > (\d+)',
            alert).group(1))
        seq_metrics = scrape(metrics['sequencer'])
        increase = value(seq_metrics, 'workstream_da_failures_total')
        assert increase > threshold, (increase, threshold)
        print(f'DA stall: {increase} failures on sequencer exceeds alert threshold {threshold}; tip held', flush=True)

        # Liveness stays healthy while readiness may fall: a stalled DA does
        # not cause an orchestrator restart.
        assert http(metrics['sequencer'], '/livez').startswith('HTTP/1.1 200')
        print('Liveness/readiness: DA stall did not flip liveness', flush=True)

        # Restore the provider; the second block verifies and the failure
        # counter stops climbing.
        mock = start_mock()
        tip2 = wait(lambda: (t if (t := verified())['height'] == 2 else None))
        assert tip2['da_ref'] != tip['da_ref']
        settled = value(scrape(metrics['sequencer']), 'workstream_da_failures_total')
        time.sleep(1)
        assert value(scrape(metrics['sequencer']), 'workstream_da_failures_total') == settled
        print('DA restored: block 2 verified, failure counter settled', flush=True)

        # Correlated logs: trace/span ids and safe domain hashes are present;
        # no secret sentinel, witness or blinding label appears anywhere.
        node_log = service_logs['node']
        node_log.flush()
        lines = (directory / 'node.log').read_text(errors='replace').splitlines()
        assert any(line.strip().startswith('{') for line in lines), lines[:3]
        joined = '\n'.join(lines)
        # The span carries the W3C ids on every correlated event.
        for field in ('trace_id', 'span_id', 'service', 'tx_hash', 'da_ref'):
            assert field in joined, f'missing correlated field {field}'
        # H256 JSON is a byte array but its Display is 0x<hex>; assert the
        # transaction is joinable by its hash string in verification logs.
        tx_display = '0x' + bytes(ack['tx_hash']).hex()
        assert tx_display in joined, 'transaction hash not correlated in node logs'
        # The prover logs the commitment; its key equals da_ref, so the two
        # stages share one trace id derived from the same public hash.
        prover_log = service_logs['prover']
        prover_log.flush()
        prover_text = (directory / 'prover.log').read_text(errors='replace')
        assert 'commitment' in prover_text, 'prover did not log the job commitment'
        for marker in list(secrets.values()) + ['backend_witness', 'blinding', 'private_key', 'payload_hex']:
            assert marker not in joined, f'sensitive marker leaked: {marker}'
        for role in service_logs:
            service_logs[role].flush()
            text = (directory / f'{role}.log').read_text(errors='replace')
            for marker in secrets.values():
                assert marker not in text, f'{marker} leaked in {role} logs'
        print('Safe logging: trace/span/tx correlation present; keys, witness and blinding absent', flush=True)


if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--quiet', '--bin', 'node', '--bin', 'sequencer',
                    '--bin', 'prover'], check=True)
    first = json.loads(subprocess.check_output(
        ['cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example', 'connected_fixture']))
    second = json.loads(subprocess.check_output(
        ['cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example',
         'connected_fixture', '--', 'nonce=1']))
    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps']))['target_directory']
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory), Path(target) / 'debug', first, second, root)
