#!/usr/bin/env python3
"""Real CLI -> ring -> vendored ShadowHook in a new native process only."""
import argparse
import json
import re
import shlex
import struct
import subprocess

import lib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--mode', choices=['native', 'art'], default='native')
    args = parser.parse_args()
    device = lib.Device(args, 'inline')
    fixture = None
    pid = None
    try:
        device.require_root()
        artifacts = {name: 'out/' + name for name in ['ij2art', 'payload.so', 'inline-fixture.so', 'inline-runner']}
        if args.mode == 'art':
            artifacts.update({'app.dex': 'out/test-app-dex/classes.dex', 'art-api-jni.so': 'out/art-api-jni.so'})
        device.push(artifacts, executables=('ij2art', 'inline-runner'))
        command = shlex.join([device.remote + '/inline-runner', device.remote + '/inline-fixture.so',
                              device.remote + '/payload.so'])
        if args.mode == 'art':
            command = lib.launch_command(
                device.remote + '/app.dex', 'org.ij2art.test.Main', 'jit',
                device.remote + '/art-api-jni.so', device.remote + '/payload.so',
                device.remote + '/inline-fixture.so')
        fixture = lib.Fixture(device, command)
        pid = fixture.await_ready(r'(?:INLINE|ART_API_TEST)_READY pid=(\d+)', timeout=20)
        ctl = lib.Ctl(device, pid, '')

        def call(name, *values, mod=None):
            return ctl.call(name, *values, lib=mod or '/inline-fixture.so')

        def add(target, proxy, slot=None):
            words = ['inline', 'add', '--in', '/inline-fixture.so', '--target', target,
                     '--replacement-in', '/inline-fixture.so', '--replacement', proxy]
            if slot:
                words += ['--original-slot', slot]
            return json.loads(ctl(*words))

        assert json.loads(ctl('inline', 'init'))['version'] == '2.0.1'
        assert json.loads(ctl('inline', 'init'))['address_only']
        assert not ctl('inline', 'list')
        assert call('native_target', 3, 2) == 11
        target_addr = hex(call('target_address'))
        original_bytes = ctl('read', target_addr, 24)
        ctl('inline', 'add', '--target', '0x1', '--replacement', '0x4', ok=False, contains='status=-40')
        ctl('inline', 'query', 999, ok=False, contains='status=-44')
        ctl('inline', 'add', '--target', 'missing', '--in', '/inline-fixture.so',
            '--replacement', '0x4', ok=False, contains='not found')
        assert not ctl('inline', 'list')

        # The proxy races with installation: original_slot must already be valid.
        assert call('start_workers') == 1
        hook = add('native_target', 'native_proxy', 'native_original')
        assert hook['state'] == 'ACTIVE'
        assert ctl('read', target_addr, 24) != original_bytes
        assert call('native_target', 3, 2) == 1011
        original = ctl('call', hook['original'], '3', '2')
        assert '= 0xb ' in original, original
        ctl('inline', 'add', '--target', hook['target'], '--replacement', hook['replacement'],
            ok=False, contains='already registered')
        ctl('inline', 'add', '--in', '/inline-fixture.so', '--target', 'native_sum10',
            '--replacement-in', '/inline-fixture.so', '--replacement', 'sum_proxy',
            '--original-slot', 'native_original', ok=False, contains='already registered')
        ctl('inline', 'add', '--in', '/inline-fixture.so', '--target', 'native_sum10',
            '--replacement-in', '/inline-fixture.so', '--replacement', 'sum_proxy',
            '--original-slot', hex(int(hook['original_slot'], 16) | (0xFF << 56)),
            ok=False, contains='already registered')
        ctl('inline', 'add', '--target', hook['target'], '--replacement', hook['replacement'],
            '--original-slot', hook['target'], ok=False, contains='non-executable original slot')
        ctl('shutdown', ok=False, contains='native inline hooks remain')
        assert call('stop_workers') == 0
        assert call('worker_calls') > 0 and call('worker_hooked') > 0
        assert json.loads(ctl('inline', 'query', hook['id'])) == hook
        assert json.loads(ctl('inline', 'del', hook['id']))['state'] == 'REMOVED'
        assert json.loads(ctl('inline', 'del', hook['id']))['state'] == 'REMOVED'
        assert call('native_target', 3, 2) == 11
        assert ctl('read', target_addr, 24) == original_bytes

        # Both endpoints supplied as raw addresses, with repeat installation.
        for _ in range(8):
            call('start_workers')
            h = json.loads(ctl('inline', 'add', '--target', hook['target'],
                              '--replacement', hook['replacement'], '--original-slot', hook['original_slot']))
            assert call('native_target', 3, 2) == 1011
            assert call('stop_workers') == 0
            ctl('inline', 'del', h['id'])
            assert call('native_target', 3, 2) == 11

        # A replacement that does not call the original needs no shared slot.
        h = add('native_target', 'constant_proxy')
        assert call('native_target', 3, 2) == 99
        ctl('inline', 'del', h['id'])
        assert call('native_target', 3, 2) == 11

        # A system ELF, distinct from the fixture's executable mapping.
        def ppid():
            return int(re.search(r'= (0x[0-9a-f]+)', ctl('call', '--in', '/libc.so', 'getppid'))[1], 16)
        before = ppid()
        h = json.loads(ctl('inline', 'add', '--target', 'getppid', '--in', '/libc.so',
                           '--replacement', 'ppid_proxy', '--replacement-in', '/inline-fixture.so',
                           '--original-slot', 'ppid_original'))
        assert ppid() == before + 1
        ctl('inline', 'del', h['id'])
        assert ppid() == before

        for target, proxy, slot, probe, before, after in [
            ('native_fp', 'fp_proxy', 'fp_original', 'probe_fp',
             struct.unpack('<Q', struct.pack('<d', 7.0))[0], struct.unpack('<Q', struct.pack('<d', 7.25))[0]),
            ('native_sum10', 'sum_proxy', 'sum_original', 'probe_sum', 385, 1385),
        ]:
            assert call(probe) == before
            h = add(target, proxy, slot)
            assert call(probe) == after
            ctl('inline', 'del', h['id'])
            assert call(probe) == before

        for kind, zero, one in [('adr', 37, 37), ('adrp', 39, 39), ('literal', 41, 41),
                                 ('branch', 43, 44), ('cbz', 53, 48), ('pac', 59, 60)]:
            target = 'reloc_' + kind
            assert call(target, 0) == zero and call(target, 1) == one
            h = add(target, kind + '_proxy', kind + '_original')
            assert call(target, 0) == zero + 100 and call(target, 1) == one + 100
            ctl('inline', 'del', h['id'])
            assert call(target, 0) == zero and call(target, 1) == one
        records = [json.loads(line) for line in ctl('inline', 'list').splitlines()]
        assert len(records) == 19 and all(r['state'] == 'REMOVED' for r in records), records

        # Agent-facing surface: --json envelopes, overview snapshot, batch mode, --wait.
        env = json.loads(ctl('--json', 'inline', 'list'))
        assert env['ok'] and len(env['data']['records']) == 19 and not env['data']['truncated']
        err = json.loads(ctl('--json', 'inline', 'query', 999, ok=False))
        assert not err['ok'] and err['error']['code'] == -44, err
        ov = json.loads(ctl('--json', 'overview'))['data']
        assert ov['proto'] == 4 and ov['payload']['pid'] == int(pid), ov
        assert len(ov['inline']['records']) == 19 and ov['lib']['records'] == []
        assert ov['dex']['records'] == [] and ov['hook']['records'] == []
        ctl('--wait', '5', 'ping', contains='pong')
        batch = subprocess.run(device.cmd + ['shell', device.root(shlex.join(
            [device.remote + '/ij2art', 'ctl', '--pid', pid, 'batch']))],
            input='["ping"]\n["lib","list"]\n# comment\n\n["bogus","cmd"]\n["inline","query","999"]\n',
            capture_output=True, text=True, timeout=30)
        lines = [json.loads(l) for l in batch.stdout.splitlines()]
        assert [l['ok'] for l in lines] == [True, True, False, False], batch.stdout
        assert lines[0]['data']['pid'] == int(pid)
        assert lines[2]['error']['code'] is None and lines[3]['error']['code'] == -44
        assert batch.returncode == 1
        assert 'batch' in device.shell(device.remote + '/ij2art help ctl').stdout

        # Library upload over the ring: staged in memfd, dlopen'd in-process.
        assert not ctl('lib', 'list')
        device.shell('echo nope > ' + device.remote + '/not-elf.bin')
        ctl('lib', 'load', device.remote + '/not-elf.bin', ok=False, contains='ELF64')
        up = json.loads(ctl('--json', 'lib', 'load', device.remote + '/inline-fixture.so', '--name', 'uplfix'))['data']
        assert up['state'] == 'LOADED' and int(up['base'], 16) != 0, up
        assert up['module'] == '/memfd:uplfix (deleted)'
        ctl('lib', 'load', device.remote + '/inline-fixture.so', '--name', 'uplfix',
            ok=False, contains='already in use')
        ctl('lib', 'unload', 999, ok=False, contains='status=-53')
        # The uploaded copy executes independently of the file-backed fixture.
        assert call('native_target', 3, 2, mod=up['module']) == 11
        # Replacement code from the uploaded library hooks the fixture's function.
        h = json.loads(ctl('inline', 'add', '--in', '/inline-fixture.so', '--target', 'native_target',
                           '--replacement-in', up['module'], '--replacement', 'constant_proxy'))
        assert call('native_target', 3, 2) == 99
        # The loader registry is the memfd module's only pin: unload is refused
        # while a hook is active, and truly unmaps once the hook is removed.
        ctl('lib', 'unload', up['id'], ok=False, contains='active inline hook')
        ctl('inline', 'del', h['id'])
        assert call('native_target', 3, 2) == 11
        assert json.loads(ctl('lib', 'unload', up['id']))['state'] == 'UNLOADED'
        ctl('call', '--in', up['module'], 'native_target', '3', '2', ok=False,
            contains='not found in the target process')
        # A never-referenced library unloads the same way.
        up2 = json.loads(ctl('lib', 'load', device.remote + '/inline-fixture.so', '--name', 'uplfix2'))
        assert up2['id'] != up['id'] and up2['state'] == 'LOADED'
        assert call('native_target', 3, 2, mod=up2['module']) == 11
        assert json.loads(ctl('lib', 'unload', up2['id']))['state'] == 'UNLOADED'
        ctl('call', '--in', up2['module'], 'native_target', '3', '2', ok=False,
            contains='not found in the target process')
        assert json.loads(ctl('lib', 'unload', up2['id']))['state'] == 'UNLOADED'  # idempotent
        libs = [json.loads(line) for line in ctl('lib', 'list').splitlines()]
        assert [r['state'] for r in libs] == ['UNLOADED', 'UNLOADED'], libs
        ctl('ping', contains='pong')
        ctl('shutdown')
        print('PASS: CLI symbol/address install, original publication under load, duplicate/error recovery, '
              '19 hooks including libc, integer/FP/stack arguments, ADR/ADRP/literal/B/CBZ/PAC relocation, removal, '
              'library upload/dlopen/unload, uploaded-code replacement, '
              '--json envelopes, overview, batch, --wait; mode=' + args.mode)
    finally:
        lib.stop_process(device, pid,
                         (device.remote + '/inline-runner',),
                         (device.remote + '/payload.so', 'org.ij2art.test.Main'))
        if fixture:
            fixture.drain()
            fixture.finish(timeout=5)
        device.remove()


if __name__ == '__main__':
    main()
