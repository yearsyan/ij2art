#!/usr/bin/env python3
"""Exercise only a newly-created app_process, never zygote or an existing App.

Run test/build-art-api.sh first, then this script with --serial DEVICE.
This validates the implemented API/SDK boundary, not an ART replacement backend.
"""
import shlex

import lib


def main():
    args = lib.arguments()
    device = lib.Device(args, 'api')
    fixture = None
    pid = None
    try:
        device.require_root('the isolated API fixture')
        device.push({
            'ij2art': 'out/ij2art', 'payload.so': 'out/payload.so',
            'art-api-jni.so': 'out/art-api-jni.so', 'app.dex': 'out/test-app-dex/classes.dex',
            'replacement.dex': 'out/test-replacement-dex/classes.dex',
        })
        command = 'CLASSPATH=' + shlex.quote(device.remote + '/app.dex') + ' ' + shlex.join([
            'app_process', '-Xcheck:jni', '/', 'org.ij2art.test.Main',
            device.remote + '/art-api-jni.so', device.remote + '/payload.so'])
        fixture = lib.Fixture(device, command)
        pid = fixture.await_ready(r'ART_API_TEST_READY pid=(\d+)', timeout=30)
        ctl = lib.Ctl(device, pid, '')

        # Exercise the native backend's signal-handler initialization in ART,
        # before SDK DEX load and the rest of the CheckJNI boundary regression.
        ctl('inline', 'init', contains='"address_only":true')
        capabilities = ctl('hook', 'init', contains='"replacement":true')
        assert '"adapter":"staticcopy-v1"' in capabilities, capabilities
        assert '"safe_install":true' in capabilities, capabilities
        assert '"physical_restore":false' in capabilities, capabilities
        assert '"delete_mode":"logical_disable"' in capabilities, capabilities
        print(capabilities)
        dex_id = ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', '731901')
        assert dex_id.isdigit() and int(dex_id) > 0
        ctl('dex', 'query', dex_id, contains='state=READY')
        ctl('dex', 'query', '--nonce', '731901', contains='dex_id=' + dex_id)
        assert ctl('dex', 'commit', dex_id) == dex_id
        assert ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', '731901') == dex_id
        ctl('dex', 'list', contains='dex_id=' + dex_id)
        target = 'org.ij2art.test.Main.target(I)I'
        replacement = 'fixture.Replacement.replace(Lorg/ij2art/HookContext;)Ljava/lang/Object;'
        ctl('hook', 'add', '--dex-id', dex_id, '--target', target,
            '--replacement', 'fixture.Replacement.wrongSignature(I)Ljava/lang/Object;',
            ok=False, contains='status=-17')
        ctl('hook', 'add', '--dex-id', dex_id, '--target', 'org.ij2art.test.Main.target(I)J',
            '--replacement', replacement, ok=False, contains='return type mismatch')
        ctl('hook', 'add', '--dex-id', '999', '--target', target, '--replacement', replacement,
            ok=False, contains='status=-12')
        # The --coverage knob is gone: hooks intercept entry-dispatched calls
        # (ENTRY_ONLY) by design, so stale invocations fail at the CLI itself.
        ctl('hook', 'add', '--dex-id', dex_id, '--target', target,
            '--replacement', replacement, '--coverage', 'FULL', ok=False,
            contains='--coverage was removed')
        ctl('dex', 'query', dex_id, contains='hook_refs=0')
        assert not ctl('hook', 'list')
        ctl('dex', 'del', dex_id)
        ctl('dex', 'query', dex_id, ok=False, contains='status=-12')
        assert not ctl('dex', 'list')
        ctl('ping', contains='pong')
        ctl('shutdown')
        print('PASS: real DEX upload/load/retry, exact method lookup, removed --coverage rejected at the CLI, no retained slots/DEX pins, delete, shutdown (CheckJNI)')
    finally:
        if pid:
            identity = device.shell('cat /proc/' + pid + '/cmdline', check=False).stdout
            if device.remote + '/payload.so' in identity and 'org.ij2art.test.Main' in identity:
                device.shell('kill -TERM ' + pid, check=False)
        if fixture:
            fixture.drain()
            fixture.finish(timeout=5)
        # This unique directory was created exclusively by this run.
        device.shell(shlex.join(['rm', '-rf', device.remote]), check=False)


if __name__ == '__main__':
    main()
