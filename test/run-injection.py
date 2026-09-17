#!/usr/bin/env python3
"""Zygote -> fixture APK regression, including targets/clear and lazy JNI readiness.

Requires root and an initially uninjected zygote. Only org.ij2art.aottest is
selected. Build build-art-api.sh, build-inline.sh and build-apk.sh --aot, then
sign the test APK.
Unlike the self-load suites this exercises the production carrier path.
"""
import json
import shlex
import struct
import tempfile
import time
from pathlib import Path

import lib


def main():
    device = lib.Device(lib.arguments(), 'injection')
    injected = False
    clean = True
    fixture_installed = False
    zygote = None
    executable = device.remote + '/ij2art'
    try:
        device.require_root('zygote injection regression')
        device.push({'ij2art': 'out/ij2art',
                     'app.apk': 'out/aot-apktest-aligned-signed.apk',
                     'replacement.dex': 'out/aot-apk-replacement.dex',
                     'inline-fixture.so': 'out/inline-fixture.so'})

        def cli(action, *args, status=False):
            nonlocal clean
            mutation = action in ('inject', 'targets', 'clear')
            if mutation:
                clean = False
            selected = ['--pid', str(zygote)] if zygote and action != 'launch' else []
            result = device.shell('cd / && ' + shlex.join([
                executable, action, *args, '--json', *selected]), check=False)
            print(action + ': ' + result.stdout.strip(), flush=True)
            if result.stderr:
                print(result.stderr.strip(), flush=True)
            value = json.loads(result.stdout)
            assert value['ok'] and (status or result.returncode == 0), result.stdout + result.stderr
            if mutation:
                clean = True
            return value['data']

        lib.apk_install(device, compile_mode='speed')
        fixture_installed = True
        device.shell('rm -f ' + lib.FLAG)
        # Multi-zygote ROMs can route this APK through either instance. Learn
        # its actual parent from a warm-up launch before pinning the regression
        # to that zygote; the two instrumented launches below remain cold starts.
        warmup = cli('launch', lib.PACKAGE, '--wait', '20')
        assert warmup['pid'], warmup
        initial = cli('status', '--targets', lib.PACKAGE, status=True)
        assert not initial['injected'], 'an existing injection session must be cleared by its owner first'
        zygote = initial['pid']
        system_server = device.shell('pidof system_server').stdout.strip()
        enforcement = device.shell('getenforce').stdout.strip()

        # An abnormal remote call must never trigger an automatic clear/retry.
        cli('inject', '--targets', lib.PACKAGE)
        injected = True
        cli('inject', '--targets', lib.PACKAGE)  # idempotence / existing USAP repair
        state = cli('status')
        assert state['targets'] == [lib.PACKAGE] and not state['targets_all_user_apps'], state

        # Explicit overrides still work, but a different build must not be used
        # to inspect or mutate an existing session. Change only the GNU note.
        carrier = bytearray((lib.REPO / 'out/carrier.so').read_bytes())
        phoff = struct.unpack_from('<Q', carrier, 32)[0]
        phent, phnum = struct.unpack_from('<HH', carrier, 54)
        changed = False
        for i in range(phnum):
            ph = phoff + i * phent
            if struct.unpack_from('<I', carrier, ph)[0] != 4:
                continue
            at = struct.unpack_from('<Q', carrier, ph + 8)[0]
            end = at + struct.unpack_from('<Q', carrier, ph + 32)[0]
            while at + 12 <= end:
                namesz, descsz, kind = struct.unpack_from('<III', carrier, at)
                name = at + 12
                desc = name + ((namesz + 3) & ~3)
                if kind == 3 and carrier[name:name + namesz] == b'GNU\0' and descsz:
                    carrier[desc] ^= 1
                    changed = True
                    break
                at = desc + ((descsz + 3) & ~3)
            if changed:
                break
        assert changed, 'carrier GNU build-id not found'
        good, bad = device.remote + '/override.so', device.remote + '/mismatched.so'
        device.raw('push', str(lib.REPO / 'out/carrier.so'), good)
        with tempfile.TemporaryDirectory(prefix='ij2art-carrier-') as local:
            path = Path(local) / 'mismatched.so'
            path.write_bytes(carrier)
            device.raw('push', str(path), bad)
        assert cli('status', '--carrier', good) == state
        for action, extra in [('status', []), ('inject', ['--targets', lib.PACKAGE]),
                              ('targets', ['--none']), ('clear', [])]:
            clean = False
            result = device.shell(shlex.join([executable, action, *extra, '--json',
                                              '--carrier', bad, '--pid', str(zygote)]), check=False)
            value = json.loads(result.stdout)
            assert result.returncode != 0 and not value['ok'] and 'carrier build mismatch' in value['error']['message'], result.stdout + result.stderr
            clean = True  # A verified identity refusal; no abnormal remote call.
            assert cli('status') == state
        device.shell(shlex.join(['rm', good, bad]))
        print('PASS: embedded carrier, explicit override and mismatched-build rejection for status/inject/targets/clear', flush=True)

        def launch():
            cli('launch', lib.PACKAGE, '--wait', '20')
            pid = device.shell('pidof ' + lib.PACKAGE).stdout.strip()
            assert pid.isdigit(), pid
            return pid

        for cycle in range(2):
            pid = launch()
            ctl = lib.Ctl(device, pid, '')
            deadline = time.monotonic() + 20
            while True:
                result = device.shell(shlex.join([
                    device.remote + '/ij2art', 'ctl', '--pid', pid, 'hook', 'init']), check=False)
                if result.returncode == 0 and '"replacement":true' in result.stdout:
                    break
                assert time.monotonic() < deadline, result.stdout + result.stderr
                time.sleep(0.1)
            assert 'pong' in ctl('ping')
            logs = device.shell('logcat -d --pid=' + pid + ' -s ij2art.apktest:I').stdout
            assert 'SELFLOAD off' in logs and 'SELFLOAD payload started' not in logs, logs
            uploaded = json.loads(ctl('lib', 'load', device.remote + '/inline-fixture.so',
                                     '--name', 'injection-fixture'))
            assert ctl.call('native_target', 3, 2, lib=uploaded['module']) == 11
            assert json.loads(ctl('lib', 'unload', uploaded['id']))['state'] == 'UNLOADED'

            def control():
                request = {'calls': [{'class': 'org.ij2art.apktest.MainActivity',
                                     'method': 'control', 'args': [{'type': 'int', 'value': 1}]}]}
                job = json.loads(ctl('--json', 'java', 'call', '--thread', 'new',
                                     '--request', json.dumps(request)))['data']
                deadline = time.monotonic() + 10
                while job['state'] in ('QUEUED', 'RUNNING'):
                    assert time.monotonic() < deadline, job
                    time.sleep(0.05)
                    job = json.loads(ctl('--json', 'java', 'query', job['id']))['data']
                assert job['state'] == 'SUCCEEDED', job
                ctl('java', 'del', job['id'])
                return job['results'][0]['value']

            assert control() == 18
            dex = ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', str(917000 + cycle))
            hook = ctl.add_hook(dex, 'org.ij2art.apktest.MainActivity.control(I)I',
                                'fixture.ReplacementApk.replace(Lorg/ij2art/HookContext;)Ljava/lang/Object;')
            assert control() == 7018
            ctl('hook', 'del', hook, contains='state=DISABLED')
            assert control() == 18
            print('PASS: carrier cold launch, lazy JNI readiness, fd library load/unload, AOT hook/callOriginal/delete; cycle=' + str(cycle + 1), flush=True)

        cli('targets', '--none')
        assert cli('status')['targets'] == []
        pid = launch()
        result = device.shell(shlex.join([device.remote + '/ij2art', 'ctl', '--pid', pid, 'ping']), check=False)
        assert result.returncode != 0 and 'ring' in result.stderr, result.stdout + result.stderr
        cli('targets', '--targets', lib.PACKAGE)
        pid = launch()
        assert 'pong' in lib.Ctl(device, pid, '')('--wait', '5', 'ping')
        renamed = device.remote + '/single-file-cli'
        device.shell(shlex.join(['mv', executable, renamed]))
        executable = renamed
        assert cli('status')['injected']
        cli('clear')
        injected = False
        final = cli('status', status=True)
        assert not final['injected'] and final['pid'] == initial['pid'], final
        assert device.shell('pidof system_server').stdout.strip() == system_server
        assert device.shell('getenforce').stdout.strip() == enforcement
        print('PASS: scoped inject/reinject, targets none/restore, clear; zygote/system_server unchanged, SELinux=' + enforcement, flush=True)
    finally:
        if fixture_installed:
            lib.apk_cleanup(device, reset=False)
        if injected and clean:
            # Ordinary fixture failures still release the session we created.
            result = device.shell(shlex.join([executable, 'clear',
                                              '--pid', str(zygote)]), check=False)
            clean = result.returncode == 0
        if clean:
            device.remove()
        else:
            print('Remote state needs inspection; preserving matching artifacts at ' + device.remote, flush=True)


if __name__ == '__main__':
    main()
