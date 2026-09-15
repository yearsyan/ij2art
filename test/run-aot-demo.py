#!/usr/bin/env python3
"""Real APK regression for interpreter and published OAT quick entries.

Build test/build-art-api.sh and test/build-apk.sh --aot, then sign
out/aot-apktest-aligned.apk as out/aot-apktest-aligned-signed.apk. Uses only the
org.ij2art.aottest fixture and a unique temporary directory on a rooted device.
"""
import re
import shlex
import time

import lib

CLASS = 'org.ij2art.apktest.MainActivity'
OWNER = CLASS + '.'
TAG = 'ij2art.apktest'


def main():
    args = lib.arguments()
    device = lib.Device(args, 'aot')
    pid = None
    try:
        device.require_root()
        device.push({'ij2art': 'out/ij2art', 'demo.apk': 'out/aot-apktest-aligned-signed.apk',
                     'replacement.dex': 'out/aot-apk-replacement.dex'})
        device.shell('am force-stop ' + lib.PACKAGE)
        install = device.shell('pm install -r ' + device.remote + '/demo.apk', timeout=120)
        assert 'Success' in install.stdout, install.stdout + install.stderr
        device.shell('touch ' + lib.FLAG)

        def logs():
            return device.raw('shell', 'logcat', '-d', '--pid=' + pid, '-s', TAG + ':I').stdout

        def wait_for(probe, timeout=40):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                result = probe()
                if result:
                    return result
                time.sleep(0.25)
            raise AssertionError('timeout waiting for fixture: ' + logs()[-5000:])

        ctl = lib.Ctl(device, '', '')

        def call(name, *values, lib_name='/libapkbridge.so'):
            return ctl.call(name, *values, lib=lib_name)

        def probe_is(tag, predicate):
            matches = re.findall(r'\b' + tag + r' .* probe=([^\s]+)', logs())
            return bool(matches and predicate(matches[-1]))

        def exercise(count):
            result = call('fixture_guard_exercise', count)
            assert result == 1, 'entry guard fixture failure code=%d' % result

        for phase, mode in enumerate(('verify', 'speed')):
            device.shell('am force-stop ' + lib.PACKAGE)
            compiled = device.shell('pm compile -m %s -f %s' % (mode, lib.PACKAGE), timeout=300)
            assert 'Success' in compiled.stdout, compiled.stdout + compiled.stderr
            pid = None
            launch = device.shell('am start -n ' + lib.PACKAGE + '/' + CLASS)
            assert 'Error' not in launch.stdout, launch.stdout + launch.stderr
            for _ in range(100):
                pid = device.shell('pidof ' + lib.PACKAGE, check=False).stdout.strip()
                if pid:
                    break
                time.sleep(0.1)
            assert pid and pid.isdigit(), 'fixture did not start'
            ctl.pid = pid
            wait_for(lambda: 'SELFLOAD payload started' in logs())
            caps = ctl('hook', 'init', contains='"aot":true')
            assert any('"entry_guard_hooks":' + str(n) in caps for n in (8, 9)), caps
            assert '"native":true' in caps, caps
            # Idempotent init must not patch a second time, or expose internal
            # guards as user-removable records / shutdown blockers.
            assert ctl('hook', 'init') == caps
            assert not ctl('inline', 'list')
            sdk = call('_ZN8ij2art6artint10sdk_backupEv', lib_name='/libpayload.so')
            assert call('fixture_capture_backup', sdk) == 1
            state = call('fixture_aot_state')
            if mode == 'speed':
                assert state & 0x1f == 0x1f, 'missing OAT method code: ' + hex(state)
                assert (state >> 8) & 0x1f == 0x1f, 'quick != OAT before hook: ' + hex(state)
            else:
                assert state & 0x1f == 0, 'verify unexpectedly has OAT: ' + hex(state)
            print('[*] %s: actual OAT/quick state=%#x, %s' % (mode, state, caps), flush=True)
            dex = ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', str(916100 + phase))

            def add(method, replacement, busy=False):
                words = ['hook', 'add', '--dex-id', dex, '--target', OWNER + method,
                         '--replacement', 'fixture.ReplacementApk.' + replacement +
                         '(Lorg/ij2art/HookContext;)Ljava/lang/Object;']
                if busy:
                    return ctl(*words, ok=False, contains='active managed frames')
                deadline = time.monotonic() + 40
                while True:
                    result = device.shell(shlex.join(
                        [device.remote + '/ij2art', 'ctl', '--pid', pid, *words]), check=False)
                    out = (result.stdout + result.stderr).strip()
                    if result.returncode == 0:
                        assert out.isdigit(), out
                        return out
                    if 'status=-18' not in out or time.monotonic() >= deadline:
                        raise AssertionError(out)
                    time.sleep(0.2)

            ids = [add('add(II)I', 'replace'),
                   add('greet(Ljava/lang/String;I)Ljava/lang/String;', 'skip'),
                   add('instanceScale(I)I', 'shift')]
            # Unbound declared native: data_ still holds the dlsym lookup stub.
            ctl('hook', 'add', '--dex-id', dex, '--target', OWNER + 'natUnbound(I)I',
                '--replacement', 'fixture.ReplacementApk.natShift(Lorg/ij2art/HookContext;)Ljava/lang/Object;',
                ok=False, contains='no registered JNI entry')
            wait_for(lambda: probe_is('NAT', lambda v: 1 <= int(v) <= 91))
            wait_for(lambda: probe_is('NATI', lambda v: 2 <= int(v) <= 77))
            wait_for(lambda: probe_is('REF', lambda v: 1003 <= int(v) <= 1018))
            wait_for(lambda: probe_is('GRT', lambda v: v == 'HOOKED[w]'))
            wait_for(lambda: probe_is('INS', lambda v: 300 <= int(v) <= 345))
            exercise(3)
            assert call('fixture_guard_watch', 3) == 1
            for hook in ids:
                query = ctl('hook', 'query', hook, contains='state=ACTIVE')
                assert int(re.search(r'hits=(\d+)', query).group(1)) > 0, query
            # Hold an actual target frame across native code: rejection must
            # leave flags/data/quick unchanged, then succeed after its return.
            call('fixture_block', 0)
            wait_for(lambda: call('fixture_block', 2) == 1)
            before = call('fixture_block_fingerprint')
            add('blocked(I)I', 'blocked', busy=True)
            assert call('fixture_block_fingerprint') == before
            call('fixture_block', 1)
            wait_for(lambda: call('fixture_block', 2) == 0)
            ids.append(add('blocked(I)I', 'blocked'))
            # Bound-native targets: static and instance, original via native backup.
            ids.append(add('natMul(II)I', 'natShift'))
            ids.append(add('natInstanceScale(I)I', 'natShift2'))
            wait_for(lambda: probe_is('NAT', lambda v: 4201 <= int(v) <= 4291))
            wait_for(lambda: probe_is('NATI', lambda v: 402 <= int(v) <= 477))
            exercise(6)
            call('fixture_guard_watch', 6)
            for hook in ids:
                ctl('hook', 'del', hook)
                wait_for(lambda: 'state=DISABLED' in ctl('hook', 'query', hook))
            wait_for(lambda: probe_is('REF', lambda v: 3 <= int(v) <= 18))
            wait_for(lambda: probe_is('GRT', lambda v: v.startswith('w#')))
            wait_for(lambda: probe_is('INS', lambda v: 0 <= int(v) <= 45))
            wait_for(lambda: probe_is('NAT', lambda v: 1 <= int(v) <= 91))
            wait_for(lambda: probe_is('NATI', lambda v: 2 <= int(v) <= 77))
            exercise(6)
            seqs = re.findall(r'AOT_GUARD result=1 seq=(\d+)', logs())
            previous = int(seqs[-1]) if seqs else 0
            ctl('shutdown')
            wait_for(lambda: any(int(s) > previous + 3 for s in re.findall(
                r'AOT_GUARD result=1 seq=(\d+)', logs())))
            text = logs()
            assert not re.search(r'AOT_GUARD result=(?!1\b)\d+', text), text
            assert not re.search(r'worker died|selfload failed|FATAL', text), text
            print('[+] %s: 6 hooks incl. bound natives (static+instance), callOriginal, '
                  'selectors and writers, old-frame rejection/retry, GC, logical DEL '
                  'and post-shutdown guards PASS' % mode, flush=True)
        print('PASS: OAT quick-code admission, native-method hooks and process-lifetime entry protection')
    finally:
        lib.apk_cleanup(device)
        device.remove()


if __name__ == '__main__':
    main()
