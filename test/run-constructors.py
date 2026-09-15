#!/usr/bin/env python3
"""Constructor regression: CheckJNI (JIT/no-JIT/opaque IDs) or a real speed APK.

Build test/build-art-api.sh. For --mode aot also build test/build-apk.sh --aot
and sign out/aot-apktest-aligned.apk as out/aot-apktest-aligned-signed.apk.
"""
import re
import time

import lib

OWNER = 'org.ij2art.test.ConstructorCases$'
TARGETS = ['Base.<init>(I)V', 'Child.<init>(ILjava/lang/String;)V',
           'Child.<init>()V', 'Throwing.<init>(I)V', 'Blocking.<init>(I)V']
REPLACEMENT = 'fixture.ConstructorReplacement.replace(Lorg/ij2art/HookContext;)Ljava/lang/Object;'


def main():
    args = lib.arguments(*lib.MODES)
    device = lib.Device(args, 'ctor')
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
                device.remote + '/jni.so', device.remote + '/payload.so', 'ctor'), echo=True)
            pid = fixture.await_ready(r'CTOR_READY pid=(\d+)')
            native_lib, payload_lib = '/jni.so', '/payload.so'
        assert pid and pid.isdigit(), 'fixture did not start'
        ctl = lib.Ctl(device, pid, native_lib)

        ctl('hook', 'init', contains='"replacement":true')
        sdk = ctl.call(lib.SDK_BACKUP, lib=payload_lib)
        ctl.expect('fixture_ctor_prepare', sdk)
        if args.mode == 'aot':
            states = [ctl.call('fixture_ctor_state', i, 0) for i in range(5)]
            assert all(s & 3 == 3 for s in states), 'constructors must have quick == OAT: ' + str(states)
            print('AOT constructor states:', states, flush=True)
        ctl.expect('fixture_ctor_run', 0)
        if args.mode in ('jit', 'debuggable'):
            ctl.call('fixture_ctor_state', 0, 1)
            for _ in range(200):
                state = ctl.call('fixture_ctor_state', 0, 0)
                if state & 4:
                    break
                time.sleep(0.05)
            assert state & 4, 'constructor was not JIT compiled: ' + str(state)
            print('Private JIT constructor state:', state, flush=True)
        dex = ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', '961710')
        for target, error in [(OWNER + 'Base.<init>(I)I', 'constructor return type'),
                              (OWNER + 'Base.<clinit>()V', 'class initializers'),
                              ('java.lang.String.<init>()V', 'StringFactory')]:
            ctl('hook', 'add', '--dex-id', dex, '--target', target,
                '--replacement', REPLACEMENT, ok=False, contains=error)
        assert not ctl('hook', 'list')

        def add(index, busy=False):
            if busy:
                ctl('hook', 'add', '--dex-id', dex, '--target', OWNER + TARGETS[index],
                    '--replacement', REPLACEMENT, ok=False, contains='active managed frames')
                return
            return ctl.add_hook(dex, OWNER + TARGETS[index], REPLACEMENT)

        ids = [add(i) for i in range(4)]
        ctl.expect('fixture_ctor_guards', 4)
        ctl.expect('fixture_ctor_run', 1)
        ctl.call('fixture_ctor_block', 0)
        for _ in range(100):
            if ctl.call('fixture_ctor_block', 2) == 1:
                break
            time.sleep(0.01)
        assert ctl.call('fixture_ctor_block', 2) == 1
        add(4, busy=True)
        ctl.call('fixture_ctor_block', 1)
        for _ in range(100):
            if ctl.call('fixture_ctor_block', 2) == 2:
                break
            time.sleep(0.01)
        assert ctl.call('fixture_ctor_block', 2) == 2
        ids.append(add(4))
        for hook in ids:
            ctl('hook', 'update', hook, '--dex-id', dex, '--replacement', REPLACEMENT,
                contains='generation=2')
        for _ in range(5):
            ctl.expect('fixture_ctor_guards', 5)
            ctl.expect('fixture_ctor_run', 1)
        for hook in ids:
            query = ctl('hook', 'query', hook, contains='state=ACTIVE')
            assert int(re.search(r'hits=(\d+)', query).group(1)) > 0, query
            ctl('hook', 'del', hook, contains='state=DISABLED')
        ctl.expect('fixture_ctor_guards', 5)
        ctl.expect('fixture_ctor_run', 0)
        ctl('shutdown')
        print('PASS: 5 constructors; same receiver, private/overloaded, this/super, final/reference '
              'fields, null return, original/handler exceptions, live-frame rejection/retry, '
              'callback update, GC, entry protection and logical disable; mode=' + args.mode, flush=True)
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
