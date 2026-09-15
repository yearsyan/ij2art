#!/usr/bin/env python3
"""JNI rebind/unregister regression: CheckJNI (JIT/no-JIT/opaque IDs) or a speed APK.

Build test/build-art-api.sh. For --mode aot also build test/build-apk.sh --aot
and sign out/aot-apktest-aligned.apk as out/aot-apktest-aligned-signed.apk.
"""
import re
import time

import lib

OWNER = 'org.ij2art.test.NativeBindingCases.'
TARGETS = ['instance(I)I', 'statik(I)I', 'syncInstance(I)I',
           'syncStatic(I)I', 'missing(I)I', 'managed(I)I']
REPLACEMENT = 'fixture.NativeBindingReplacement.replace(Lorg/ij2art/HookContext;)Ljava/lang/Object;'


def main():
    args = lib.arguments(*lib.MODES)
    device = lib.Device(args, 'binding')
    fixture = None
    pid = None
    try:
        artifacts = {'ij2art': 'out/ij2art'}
        if args.mode == 'aot':
            artifacts.update({'app.apk': 'out/aot-apktest-aligned-signed.apk',
                              'replacement.dex': 'out/aot-apk-replacement.dex'})
        else:
            artifacts.update({'app.dex': 'out/test-hookapp-dex/classes.dex',
                              'jni.so': 'out/art-api-jni.so', 'payload.so': 'out/payload.so',
                              'replacement.dex': 'out/test-replacement-dex/classes.dex'})
        device.push(artifacts)
        if args.mode == 'aot':
            lib.apk_install(device)
            pid = lib.apk_launch(device)
            native_lib, payload_lib = '/libapkbridge.so', '/libpayload.so'
        else:
            fixture = lib.Fixture(device, lib.launch_command(
                device.remote + '/app.dex', 'org.ij2art.test.FixtureMain', args.mode,
                device.remote + '/jni.so', device.remote + '/payload.so', 'binding'), echo=True)
            pid = fixture.await_ready(r'BINDING_READY pid=(\d+)')
            native_lib, payload_lib = '/jni.so', '/payload.so'
        assert pid and pid.isdigit(), 'fixture did not start'
        ctl = lib.Ctl(device, pid, native_lib)

        caps = ctl('hook', 'init', contains='"native_binding_guard":true')
        assert any('"entry_guard_hooks":' + str(n) in caps for n in (8, 9)), caps
        sdk = ctl.call(lib.SDK_BACKUP, lib=payload_lib)
        ctl.expect('fixture_binding_prepare', sdk)
        ctl.expect('fixture_binding_run', 0, 7, 0)
        dex = ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', '961710')
        assert not ctl('hook', 'list')
        ids = [ctl.add_hook(dex, OWNER + target, REPLACEMENT) for target in TARGETS]
        ctl.expect('fixture_binding_check', 1)

        def exercise(hooked):
            for _ in range(2):
                for action, value, unbound in [(0, 7, 0), (1, 70, 0), (2, 700, 1), (1, 70, 0)]:
                    ctl.expect('fixture_binding_bind', action)
                    ctl.expect('fixture_binding_check', 0)
                    ctl.expect('fixture_binding_run', hooked, value, unbound)
                    ctl.expect('fixture_binding_check', 0)
            ctl.expect('fixture_binding_race', hooked)
            ctl.expect('fixture_binding_check', 0)
            ctl.expect('fixture_binding_callbacks', 1)
            ctl.expect('fixture_binding_bind', 1)
            assert ctl.call('fixture_binding_callbacks', 2) == 0x3f, 'binding callback identity changed'
            ctl.expect('fixture_binding_run', hooked, 900, 0)
            ctl.expect('fixture_binding_callbacks', 1)  # reset observation mask
            ctl.expect('fixture_binding_bind', 2)
            ctl.expect('fixture_binding_run', hooked, 900, 1)
            assert ctl.call('fixture_binding_callbacks', 2) == 0x2f, 'lazy resolution exposed backup identity'
            ctl.expect('fixture_binding_callbacks', 0)
            ctl.expect('fixture_binding_check', 0)

        exercise(1)
        for hook in ids:
            query = ctl('hook', 'query', hook, contains='state=ACTIVE')
            assert int(re.search(r'hits=(\d+)', query).group(1)) > 0, query
        for hook in ids:
            ctl('hook', 'del', hook, contains='state=DISABLED')
        exercise(0)
        ctl.expect('fixture_binding_watch')
        observed = ''
        def sequence():
            nonlocal observed
            if args.mode == 'aot':
                observed = device.raw('shell', 'logcat', '-d', '--pid=' + pid).stdout
            else:
                while not fixture.lines.empty():
                    line = fixture.lines.get_nowait()
                    assert line is not None, 'fixture exited during watch'
                    observed += line
            assert 'NATIVE_BINDING_WATCH FAIL' not in observed, observed
            matches = re.findall(r'NATIVE_BINDING_WATCH PASS seq=(\d+)', observed)
            return int(matches[-1]) if matches else 0
        deadline = time.monotonic() + 30
        while sequence() < 1:
            assert time.monotonic() < deadline, observed
            time.sleep(0.1)
        before = sequence()
        ctl('shutdown')
        while sequence() < before + 4:
            assert time.monotonic() < deadline, observed
            time.sleep(0.1)
        print('PASS: %d JNI binding hooks; re-register, whole-class unregister, lazy symbol '
              'resolution and missing-symbol errors, synchronized originals, managed sibling/control, '
              'ART binding callbacks, concurrent binding, logical disable and post-shutdown protection; mode=%s'
              % (len(ids), args.mode), flush=True)
    except BaseException:
        if fixture:
            fixture.dump()
        elif pid:
            print(device.shell('logcat -d --pid=' + pid + ' -t 150', check=False).stdout[-15000:],
                  flush=True)
        raise
    finally:
        if args.mode == 'aot':
            lib.apk_cleanup(device)
        else:
            lib.stop_process(device, pid, (device.remote, 'FixtureMain'))
        if fixture:
            fixture.finish()
        device.remove()


if __name__ == '__main__':
    main()
