"""Projection drill: mid-batch restart, rebuild, pagination and non-authority."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import socket
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
                json.JSONDecodeError):
            pass
        time.sleep(.1)
    raise TimeoutError('projection drill did not reach expected state')


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run(directory, binaries, fixtures, unauthorized):
    pki = directory / 'identities'
    subprocess.run(['bash', 'scripts/dev-service-identities.sh', pki], check=True,
                   stdout=subprocess.DEVNULL)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1', 0))
        rpc_port = reserve.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith('WORKSTREAM_')}
    env.update({
        'WORKSTREAM_PROFILE': 'dev',
        'WORKSTREAM_RUNTIME_DIR': str(directory),
        'WORKSTREAM_NODE_RPC_PORT': str(rpc_port),
    })
    data = directory / 'writer-data'
    data.mkdir(mode=0o700)
    env['WORKSTREAM_WRITER_DATA'] = str(data)
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

    def receipt(tx_hash):
        return rpc('workstream.node.getReceipt', {'tx_hash': tx_hash})

    with contextlib.ExitStack() as cleanup:
        sock_dir, pg_port, proofjobs = connected.start_postgres(directory, cleanup)
        projections = proofjobs.copy()
        projections[-1] = 'projections'
        env['WORKSTREAM_JOBS_SOCKET'] = str(sock_dir)
        env['WORKSTREAM_JOBS_PORT'] = str(pg_port)
        env['WORKSTREAM_PROJECTIONS_SOCKET'] = str(sock_dir)
        env['WORKSTREAM_PROJECTIONS_PORT'] = str(pg_port)

        def sql(query, database=projections):
            return subprocess.check_output(database + ['-At', '-c', query], text=True).strip()

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

        def status():
            reply = rpc('workstream.indexer.getStatus')
            assert 'error' not in reply, reply
            return reply['result']

        def page(kind, cursor='', limit=5, event_type=''):
            reply = rpc('workstream.indexer.getPage', {
                'kind': kind, 'cursor': cursor, 'limit': limit,
                'event_type': event_type})
            assert 'error' not in reply, reply
            return reply['result']

        def snapshot():
            return {
                'events': sql("SELECT count(*)||':'||coalesce(md5(string_agg(t::text,'|' ORDER BY height,tx_index,ordinal)),'') FROM projection_events t"),
                'work_items': sql("SELECT count(*)||':'||coalesce(md5(string_agg(t::text,'|' ORDER BY height,tx_index,ordinal)),'') FROM projection_work_items t"),
                'grants': sql("SELECT count(*)||':'||coalesce(md5(string_agg(t::text,'|' ORDER BY grantee,grantor,capability)),'') FROM projection_grants t"),
                'reviews': sql("SELECT count(*)||':'||coalesce(md5(string_agg(t::text,'|' ORDER BY height,tx_index,ordinal)),'') FROM projection_reviews t"),
                'receipts': sql("SELECT count(*)||':'||coalesce(md5(string_agg(t::text,'|' ORDER BY height,tx_hash)),'') FROM projection_receipts t"),
            }

        start('sequencer')
        start('prover')
        start('node', 'projection-mid-batch')
        wait(verified)

        # A crash before the projection transaction commits leaves no cursor
        # and no partial rows. The first verified block is replayed by the
        # restarted verifier from the writer's durable journal.
        ack = submit(fixtures[0])['result']
        assert ack['status'] == 'Pending'
        wait(lambda: processes['node'].poll() is not None)
        assert sql("SELECT indexed_height||'|'||verified_height FROM projection_meta WHERE chain='1'") == '0|0'
        assert sql('SELECT count(*) FROM projection_events') == '0'
        print('Mid-batch crash: projection cursor and rows both rolled back', flush=True)
        stop('node')

        start('node')
        wait(lambda: (t if (t := verified())['height'] == 1 else None))
        assert status()['indexed_height'] == 1 and status()['lag'] == 0
        print('Mid-batch restart: verifier replayed block 1 and indexed it once', flush=True)

        for fixture in fixtures[1:]:
            submit(fixture)
        tip = wait(lambda: (t if (t := verified())['height'] == len(fixtures) else None))
        state = wait(lambda: (s if (s := status())['indexed_height'] == len(fixtures) else None))
        assert state['verified_height'] == tip['height'] and state['lag'] == 0
        before = snapshot()
        for table, value in before.items():
            count = int(value.split(':', 1)[0])
            assert count > 0, (table, value)
        assert before['events'].startswith(f'{len(fixtures)}:')
        assert before['receipts'].startswith(f'{len(fixtures)}:')
        print(f'Indexed {len(fixtures)} events and receipts, {before["grants"].split(":",1)[0]} grants, {before["reviews"].split(":",1)[0]} reviews', flush=True)

        # Cursor pagination returns every event exactly once, independent of
        # the verified tip.
        collected = []
        cursor = ''
        for _ in range(20):
            result = page('events', cursor, 5)
            collected.extend((item['height'], item['tx_index'], item['ordinal'])
                             for item in result['items'])
            cursor = result['next_cursor']
            if not cursor:
                break
        assert len(collected) == len(fixtures) == len(set(collected))
        filtered = page('events', '', 20, 'actor.granted')
        assert len(filtered['items']) == 2
        assert all(item['event_type'] == 'actor.granted' for item in filtered['items'])
        print('Pagination: cursor walk and event-type filter returned stable, unique rows', flush=True)

        def reindex():
            # Rebuild requires exclusive ownership, so the live verifier must
            # be stopped first. Killing it closes its database socket and
            # releases the advisory lock; retry briefly for that handoff.
            stop('node')
            for _ in range(30):
                result = subprocess.run([binaries / 'workstream-reindex'], env=env,
                                        capture_output=True, text=True)
                if result.returncode == 0:
                    return json.loads(result.stdout)
                if 'another projection indexer owns this chain' in result.stderr:
                    time.sleep(.1)
                    continue
                raise AssertionError(f'reindex failed: {result.stderr}')
            raise AssertionError('reindex never acquired the projection owner lock')

        def restart_node():
            start('node')
            wait(lambda: (t if (t := verified())['height'] == len(fixtures) else None))
            wait(lambda: (s if (s := status())['indexed_height'] == len(fixtures)
                          and s['lag'] == 0 else None))

        # Wipe derived tables and rebuild from the immutable verified log.
        replay_status = reindex()
        after = snapshot()
        assert after == before
        assert replay_status['indexed_height'] == len(fixtures)
        assert replay_status['lag'] == 0
        print('Wipe/rebuild: all five projection tables match the original snapshot', flush=True)

        restart_node()

        # Projection edits are read-model edits only. A forged active grant in
        # PostgreSQL must not authorize a chain action.
        reviewer = json.loads(subprocess.check_output([
            'cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example',
            'projection_fixture', '--', 'unauthorized-claim']))
        reviewer_account = bytes(reviewer['account']).hex()
        # H256 serializes as an array of 32 bytes; encode it as Postgres hex.
        sql("DELETE FROM projection_grants WHERE grantee=decode('" + reviewer_account + "','hex')")
        sql("INSERT INTO projection_grants(chain,grantee,grantor,capability,active,height,tx_index,ordinal,tx_hash) "
            "SELECT '1', decode('" + reviewer_account + "','hex'), grantor, 'ClaimWork', true, 1, 99, 0, tx_hash "
            "FROM projection_grants LIMIT 1")
        forged = page('grants', '', 20)
        assert any(item['grantee'] == reviewer_account
                   and item['active'] for item in forged['items'])
        ack = submit(unauthorized)['result']
        assert ack['status'] == 'Pending'
        tx_hash = ack['tx_hash']
        outcome = wait(lambda: (r if (r := receipt(tx_hash))['result']['status'] == 'Rejected' else None))
        assert outcome['result']['status'] == 'Rejected'
        print('Projection authority: forged grant visible in read model, chain rejected the action', flush=True)

        # Rebuild removes the forged row without changing the verified chain.
        replay_status = reindex()
        assert snapshot() == before
        assert replay_status['verified_height'] == len(fixtures)
        print('Authority rebuild: forged projection row removed; authoritative tip unchanged', flush=True)


if __name__ == '__main__':
    subprocess.run(['cargo', 'build', '--quiet', '--bin', 'node', '--bin', 'sequencer',
                    '--bin', 'prover', '--bin', 'workstream-reindex'], check=True)
    raw = subprocess.check_output(['cargo', 'run', '--quiet', '-p', 'workstream-tests',
                                   '--example', 'projection_fixture'])
    fixtures = json.loads(raw)
    unauthorized = json.loads(subprocess.check_output([
        'cargo', 'run', '--quiet', '-p', 'workstream-tests', '--example',
        'projection_fixture', '--', 'unauthorized-claim']))
    target = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--format-version', '1', '--no-deps']))['target_directory']
    with tempfile.TemporaryDirectory() as directory:
        run(Path(directory), Path(target) / 'debug', fixtures, unauthorized)
