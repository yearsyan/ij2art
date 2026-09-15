#!/usr/bin/env python3
"""Live callback updates: overlapping old/new calls, DEX retirement and lifecycle races.

Build test/build-art-api.sh. For --mode aot also build test/build-apk.sh --aot
and sign out/aot-apktest-aligned.apk as out/aot-apktest-aligned-signed.apk.
"""
import re
import time

import lib

OWNER = 'org.ij2art.test.HookUpdateCases.'
TARGETS = ['staticValue(I)I', 'instanceValue(I)I', 'syncValue(I)I', 'nativeValue(I)I']
SIGNATURE = '(Lorg/ij2art/HookContext;)Ljava/lang/Object;'
REPLACEMENT = 'fixture.UpdateReplacement.replace' + SIGNATURE


def main():
    args = lib.arguments(*lib.MODES)
    device = lib.Device(args, 'update')
    fixture = None
    pid = None
    try:
        artifacts = {'ij2art': 'out/ij2art', 'a.dex': 'out/update-a-dex/classes.dex',
                     'b.dex': 'out/update-b-dex/classes.dex'}
        if args.mode == 'aot':
            artifacts.update({'app.apk': 'out/aot-apktest-aligned-signed.apk'})
        else:
            artifacts.update({'app.dex': 'out/test-hookapp-dex/classes.dex',
                              'jni.so': 'out/art-api-jni.so', 'payload.so': 'out/payload.so'})
        device.push(artifacts)
        if args.mode == 'aot':
            lib.apk_install(device)
            pid = lib.apk_launch(device)
            native_lib, payload_lib = '/libapkbridge.so', '/libpayload.so'
        else:
            fixture = lib.Fixture(device, lib.launch_command(
                device.remote + '/app.dex', 'org.ij2art.test.FixtureMain', args.mode,
                device.remote + '/jni.so', device.remote + '/payload.so', 'update'), echo=True)
            pid = fixture.await_ready(r'UPDATE_READY pid=(\d+)')
            native_lib, payload_lib = '/jni.so', '/payload.so'
        assert pid and pid.isdigit(), 'fixture did not start'
        ctl = lib.Ctl(device, pid, native_lib)

        ctl('hook', 'init', contains='"replacement_update":true')
        sdk = ctl.call(lib.SDK_BACKUP, lib=payload_lib)
        ctl.expect('fixture_update_prepare', sdk)
        dex = ctl('dex', 'upload', device.remote + '/a.dex', '--nonce', '971601')
        newer = ctl('dex', 'upload', device.remote + '/b.dex', '--nonce', '971602')
        assert not ctl('hook', 'list')
        ids = [ctl.add_hook(dex, OWNER + target, REPLACEMENT) for target in TARGETS]
        generations = [1] * len(ids)
        ctl.expect('fixture_update_metadata', 1)

        def update(index, dex_id, method='replace', state='ACTIVE'):
            result = ctl('hook', 'update', ids[index], '--dex-id', dex_id,
                         '--replacement', 'fixture.UpdateReplacement.' + method + SIGNATURE,
                         contains='state=' + state)
            generations[index] += 1
            assert 'generation=' + str(generations[index]) in result, result
            assert 'hook_id=' + ids[index] in result, result
            return result

        def refs(dex_id, count):
            ctl('dex', 'query', dex_id, contains='hook_refs=' + str(count) + ' ')

        def wait_blocked(index):
            ctl.expect('fixture_update_block', 0, index)
            deadline = time.monotonic() + 15
            while ctl.call('fixture_update_block', 2, index) != 1:
                assert time.monotonic() < deadline, 'old original did not block'
                time.sleep(0.02)

        for i in range(4):
            ctl.expect('fixture_update_probe', i, 5, 115)
        wait_blocked(0)
        for i in range(4):
            update(i, newer)
            ctl.expect('fixture_update_probe', i, 5, 215)
            ctl.expect('fixture_update_probe', i, 98, -1)
            ctl.expect('fixture_update_probe', i, 99, 1199)
        ctl.expect('fixture_update_metadata', 0)
        refs(dex, 1)
        ctl('dex', 'del', dex, ok=False, contains='status=-18')
        # Lookup/signature/class-init failures leave the working version intact.
        for target, dex_id in [
            ('fixture.Missing.replace' + SIGNATURE, newer),
            ('fixture.UpdateReplacement.invalid(I)I', newer),
            ('fixture.FailingReplacement.replace' + SIGNATURE, newer),
            (REPLACEMENT, '18446744073709551615'),
        ]:
            ctl('hook', 'update', ids[0], '--dex-id', dex_id, '--replacement', target, ok=False)
            ctl('hook', 'query', ids[0], contains='generation=2')
            ctl.expect('fixture_update_probe', 0, 5, 215)
        ctl('hook', 'update', '18446744073709551615', '--dex-id', newer,
            '--replacement', REPLACEMENT, ok=False, contains='status=-12')
        # DEL counts old-version leases as well as current-version calls.
        ctl('hook', 'del', ids[0], contains='state=DRAINING')
        update(0, newer, 'alternate', state='DRAINING')
        ctl.expect('fixture_update_probe', 0, 5, 15)
        ctl.expect('fixture_update_block', 1, 0)  # old A, callOriginal and recursive bypass still work
        ctl('hook', 'query', ids[0], contains='state=DISABLED')
        refs(dex, 0)
        ctl('dex', 'del', dex)
        refs(newer, 4)
        for method, exception in [('throwing', -2), ('wrong', -3)]:
            update(1, newer, method)
            ctl.expect('fixture_update_probe', 1, 5, exception)
            ctl('hook', 'query', ids[1], contains='in_flight=0')
        update(1, newer)
        # Readers remain active during many updates; every result must belong to
        # exactly one callback version, while monitor/native original paths work.
        ctl.expect('fixture_update_race', 1)
        for n in range(18):
            update(1 + n % 3, newer, 'alternate' if n & 1 else 'replace')
        ctl.expect('fixture_update_race', 0)
        refs(newer, 4)
        ctl.expect('fixture_update_metadata', 0)
        # Cycle more than the 16 DEX slots using equal class names in distinct
        # loaders. Old callback roots/DEX charges must actually become droppable.
        current_dex = newer
        for n in range(18):
            fresh = ctl('dex', 'upload', device.remote + '/a.dex', '--nonce', str(971700 + n))
            for i in range(4):
                update(i, fresh, state='DISABLED' if i == 0 else 'ACTIVE')
                ctl.expect('fixture_update_probe', i, 5, 15 if i == 0 else 115)
            refs(current_dex, 0)
            ctl('dex', 'del', current_dex)
            current_dex = fresh
        refs(current_dex, 4)
        assert len(re.findall(r'hook_id=', ctl('hook', 'list'))) == 4
        ctl.expect('fixture_update_metadata', 0)
        # Shutdown closes future updates but retains in-flight old contexts.
        wait_blocked(1)
        ctl('shutdown', ok=False, contains='status=-18')
        ctl('hook', 'update', ids[1], '--dex-id', current_dex, '--replacement', REPLACEMENT,
            ok=False, contains='updates are closed')
        ctl.expect('fixture_update_block', 1, 1)
        for i in range(4):
            ctl.expect('fixture_update_probe', i, 5, 15)
        ctl.expect('fixture_update_metadata', 0)
        ctl('shutdown')
        print('PASS: live callback updates; old/new overlap, original/recursion tokens, JNI and '
              'synchronized calls, failure rollback, concurrent updates, DEX reclamation beyond '
              '16 loads, DEL/shutdown, stable ArtMethods and 4 permanent slots; mode=' + args.mode,
              flush=True)
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
