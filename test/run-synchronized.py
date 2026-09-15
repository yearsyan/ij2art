#!/usr/bin/env python3
"""Synchronized-method regression: CheckJNI (JIT/no-JIT/opaque IDs) or a real speed APK.

Build test/build-art-api.sh. For --mode aot also build test/build-apk.sh --aot
and sign out/aot-apktest-aligned.apk as out/aot-apktest-aligned-signed.apk.
"""
import re
import time

import lib

OWNER = 'org.ij2art.test.SynchronizedCases.'
TARGETS = ['instance(I)I', 'staticValue(I)I', 'blocking(I)I',
           'nativeInstance(I)I', 'nativeStatic(I)I']
REPLACEMENT = 'fixture.SynchronizedReplacement.replace(Lorg/ij2art/HookContext;)Ljava/lang/Object;'


def main():
    args = lib.arguments(*lib.MODES)
    device = lib.Device(args, 'sync')
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
                device.remote + '/jni.so', device.remote + '/payload.so', 'sync'), echo=True)
            pid = fixture.await_ready(r'SYNC_READY pid=(\d+)')
            native_lib, payload_lib = '/jni.so', '/payload.so'
        assert pid and pid.isdigit(), 'fixture did not start'
        ctl = lib.Ctl(device, pid, native_lib)

        ctl('hook', 'init', contains='"replacement":true')
        sdk = ctl.call(lib.SDK_BACKUP, lib=payload_lib)
        ctl.expect('fixture_sync_prepare', sdk)
        if args.mode == 'aot':
            states = [ctl.call('fixture_sync_state', i, 0) for i in range(3)]
            assert all(s & 3 == 3 for s in states), 'managed synchronized methods must have quick == OAT: ' + str(states)
            print('AOT synchronized states:', states, flush=True)
        ctl.expect('fixture_sync_run', 0)
        if args.mode in ('jit', 'debuggable'):
            ctl.call('fixture_sync_state', 0, 1)
            for _ in range(200):
                state = ctl.call('fixture_sync_state', 0, 0)
                if state & 4:
                    break
                time.sleep(0.05)
            assert state & 4, 'synchronized method was not JIT compiled: ' + str(state)
            print('Private JIT synchronized state:', state, flush=True)
        dex = ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', '961710')
        assert not ctl('hook', 'list')

        def add(index, busy=False):
            if busy:
                ctl('hook', 'add', '--dex-id', dex, '--target', OWNER + TARGETS[index],
                    '--replacement', REPLACEMENT, ok=False, contains='active managed frames')
                return
            return ctl.add_hook(dex, OWNER + TARGETS[index], REPLACEMENT)

        ids = [add(i) for i in range(2)]
        ctl.call('fixture_sync_block', 0)
        for _ in range(100):
            if ctl.call('fixture_sync_block', 2) == 1:
                break
            time.sleep(0.01)
        assert ctl.call('fixture_sync_block', 2) == 1
        add(2, busy=True)
        ctl.call('fixture_sync_block', 1)
        for _ in range(100):
            if ctl.call('fixture_sync_block', 2) == 2:
                break
            time.sleep(0.01)
        assert ctl.call('fixture_sync_block', 2) == 2
        ids.append(add(2))
        ids.extend(add(i) for i in range(3, 5))
        ctl.expect('fixture_sync_run', 1)
        for _ in range(2):
            ctl.expect('fixture_sync_guards', len(ids))
            ctl.expect('fixture_sync_run', 1)
        for hook in ids:
            query = ctl('hook', 'query', hook, contains='state=ACTIVE')
            assert int(re.search(r'hits=(\d+)', query).group(1)) > 0, query
        # DEL while the synchronized original is waiting must drain without
        # waiting for its monitor, and the in-flight callback still completes.
        ctl.call('fixture_sync_drain', 0)
        for _ in range(200):
            if ctl.call('fixture_sync_drain', 2) == 1:
                break
            time.sleep(0.01)
        assert ctl.call('fixture_sync_drain', 2) == 1
        ctl('hook', 'del', ids[0], contains='state=DRAINING')
        assert ctl.call('fixture_sync_drain', 1) == 2
        ctl('hook', 'query', ids[0], contains='state=DISABLED')
        for hook in ids[1:]:
            ctl('hook', 'del', hook, contains='state=DISABLED')
        ctl.expect('fixture_sync_guards', len(ids))
        ctl.expect('fixture_sync_run', 0)
        ctl('shutdown')
        print('PASS: %d synchronized hooks; instance/Class monitors, contention, skip/repeated '
              'original, reentry, wait/notify from original and handler, exception unlock, '
              'old-frame rejection/retry, GC, entry protection and concurrent logical disable; mode=%s'
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
