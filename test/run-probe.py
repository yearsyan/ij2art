#!/usr/bin/env python3
"""Instruction probes through the real CLI/payload, in a new isolated process only."""
import json
import shlex
import struct
import time

import lib


def main():
    args = lib.arguments()
    device = lib.Device(args, 'probe')
    fixture = None
    pid = None
    try:
        device.require_root()
        device.push({name: 'out/' + name for name in
                     ('ij2art', 'payload.so', 'inline-fixture.so', 'inline-runner')},
                    executables=('ij2art', 'inline-runner'))
        fixture = lib.Fixture(device, shlex.join([
            device.remote + '/inline-runner', device.remote + '/inline-fixture.so',
            device.remote + '/payload.so']))
        pid = fixture.await_ready(r'INLINE_READY pid=(\d+)')
        ctl = lib.Ctl(device, pid, '/inline-fixture.so')

        def command(*words, **kwargs):
            env = json.loads(ctl('--json', 'probe', *words, **kwargs))
            return env.get('data', env.get('error'))

        def add(*extra):
            return command('add', '--target', 'probe_target', '--in', '/inline-fixture.so',
                           '--offset', '0x10', *extra)

        def read(probe_id, after=0, limit=48):
            for _ in range(100):
                # The writer never blocks; a busy read is explicitly retryable.
                result = device.shell(shlex.join([
                    device.remote + '/ij2art', 'ctl', '--pid', pid, '--json', 'probe', 'read',
                    str(probe_id), '--after', str(after), '--limit', str(limit)]), check=False)
                env = json.loads(result.stdout)
                if env['ok']:
                    return env['data']
                assert env['error']['code'] == -75, env
                time.sleep(0.01)
            raise AssertionError('probe buffer stayed busy')

        assert command('list')['records'] == []
        assert ctl.call('probe_target', 3, 2) == 8
        assert ctl.call('probe_target', 1, 3) == 3
        pc = ctl.call('probe_target_address') + 0x10
        original = ctl('read', hex(pc), '4')
        command('add', '--target', '0x1', ok=False)
        command('query', 999, ok=False, contains='status=-74')
        command('add', '--target', hex(pc), '--tid', '2147483647', ok=False,
                contains='does not belong')
        assert command('list')['records'] == []

        p = add('--when', 'x0=3', '--max-hits', '2')
        assert p['target'] == hex(pc) and p['state'] == 'ACTIVE'
        assert ctl('read', hex(pc), '4') != original
        assert ctl.call('probe_target', 1, 3) == 3  # filtered out
        assert ctl.call('probe_target', 3, 2) == 8
        assert ctl.call('probe_target', 3, 2) == 8
        assert ctl.call('probe_target', 3, 2) == 8  # hit limit
        batch = read(p['id'])
        assert batch['probe']['state'] == 'LIMITED' and batch['probe']['hits'] == 2, batch
        assert len(batch['events']) == 2 and batch['lost'] == 0 and not batch['more']
        worker_tid = ctl.call('fixture_tid')
        for e in batch['events']:
            assert e['pc'] == hex(pc) and e['tid'] == worker_tid
            assert int(e['sp'], 16) % 16 == 0 and int(e['regs']['x30'], 16)
            assert e['nzcv'] == '0x20000000' and e['ts_ns'] > 0 and not e['clock_failed']
            assert [e['regs'][f'x{i}'] for i in (0, 1, 9, 16, 17)] == ['0x3', '0x2', '0xa', '0x1616', '0x1717']
        assert read(p['id']) == batch
        assert read(p['id'], 2)['events'] == []
        command('read', p['id'], '--after', 3, ok=False, contains='status=-70')
        command('add', '--target', hex(pc), ok=False, contains='already registered')
        ctl('inline', 'add', '--target', hex(pc), '--replacement', hex(pc - 0x10),
            ok=False, contains='instruction probe')
        ctl('shutdown', ok=False, contains='instruction probes remain')
        ov = json.loads(ctl('--json', 'overview'))['data']
        assert ov['probe']['count'] == 1 and ov['probe']['records'][0]['state'] == 'LIMITED'
        assert command('del', p['id'])['state'] == 'REMOVED'
        assert command('del', p['id'])['state'] == 'REMOVED'
        assert ctl('read', hex(pc), '4') == original
        assert ctl.call('probe_target', 3, 2) == 8
        assert read(p['id'])['events'] == batch['events']  # retained after deletion

        # Thread filtering distinguishes the sleeping main thread from the control worker.
        for tid, expected in ((int(pid), 0), (worker_tid, 1)):
            p = add('--tid', str(tid))
            assert ctl.call('probe_target', 3, 2) == 8
            assert command('query', p['id'])['hits'] == expected
            command('del', p['id'])

        # Module RVA addressing and ring overwrite/pagination, without per-hit RPCs.
        maps = device.shell('cat /proc/' + pid + '/maps').stdout.splitlines()
        base = next(int(line.split('-')[0], 16) for line in maps
                    if line.split()[2] == '00000000' and line.endswith('/inline-fixture.so'))
        p = command('add', '--in', '/inline-fixture.so', '--offset', hex(pc - base))
        assert p['target'] == hex(pc)
        assert ctl.call('probe_loop', 400) == 8000
        batch = read(p['id'], limit=7)
        assert batch['lost'] == 144 and batch['probe']['overwritten'] == 144, batch
        events = batch['events']
        while batch['more']:
            batch = read(p['id'], batch['next_seq'])
            assert batch['lost'] == 0
            events += batch['events']
        assert [e['seq'] for e in events] == list(range(145, 401))
        assert all(e['regs']['x0'] == '0x9' and e['regs']['x1'] == '0x4' for e in events)
        command('del', p['id'])

        # Observe with live SIMD registers; floating-point output must be unchanged.
        expected = struct.unpack('<Q', struct.pack('<d', 3.0))[0]
        assert ctl.call('probe_simd') == expected
        p = command('add', '--target', 'probe_simd', '--in', '/inline-fixture.so', '--offset', '8')
        assert ctl.call('probe_simd') == expected
        assert len(read(p['id'])['events']) == 1
        command('del', p['id'])
        assert ctl.call('probe_simd') == expected

        # Four producer threads: bounded counters and intact snapshots under contention.
        p = command('add', '--target', 'native_target', '--in', '/inline-fixture.so', '--max-hits', '4096')
        assert ctl.call('start_workers') == 1
        try:
            for _ in range(50):
                q = command('query', p['id'])
                if q['state'] == 'LIMITED':
                    break
                time.sleep(0.02)
        finally:
            assert ctl.call('stop_workers') == 0
        q = command('query', p['id'])
        assert q['state'] == 'LIMITED' and q['hits'] == 4096, q
        assert q['captured'] + q['dropped'] == 4096, q
        assert q['captured'] > 0
        assert all(e['regs']['x0'] == '0x3' and e['regs']['x1'] == '0x2'
                   for e in read(p['id'])['events'])
        command('del', p['id'])

        # A probe pins uploaded code until removed, including when collection is LIMITED.
        up = json.loads(ctl('--json', 'lib', 'load', device.remote + '/inline-fixture.so', '--name', 'probe-fixture'))['data']
        p = command('add', '--target', 'probe_target', '--in', up['module'], '--offset', '0x10', '--max-hits', 1)
        assert ctl.call('probe_target', 3, 2, lib=up['module']) == 8
        assert command('query', p['id'])['state'] == 'LIMITED'
        ctl('lib', 'unload', up['id'], ok=False, contains='instruction probe')
        command('del', p['id'])
        ctl('lib', 'unload', up['id'])
        assert len(read(p['id'])['events']) == 1
        records = command('list')['records']
        assert len(records) == 7 and all(r['state'] == 'REMOVED' for r in records), records
        ctl('shutdown')
        print('PASS: instruction/address/RVA probes, pre-instruction GPR/NZCV and live SIMD preservation, '
              'conditions, thread filters, limits, concurrent capture, overflow/cursors, restore, '
              'JSON/overview, uploaded module lifetime')
    finally:
        lib.stop_process(device, pid, (device.remote + '/inline-runner',), ())
        if fixture:
            fixture.drain()
            fixture.finish(timeout=5)
        device.remove()


if __name__ == '__main__':
    main()
