#!/usr/bin/env python3
"""Strict-install admission regression on a real device, in a disposable app_process.

staticcopy-v1 retires private JIT/OSR code and rejects active managed frames.
Logical disable is tested separately by run-static-jni.py --logical-disable.

Run test/build-art-api.sh first, then this script with --serial DEVICE.
The fixture is phase-file driven; every CLI action is followed by exact
behavioral assertions inside the App. Never touches zygote or existing Apps.
"""
import re
import shlex
import time

import lib


def main():
    args = lib.arguments('jit', 'no-jit', 'debuggable')
    device = lib.Device(args, 'hook')
    fixture = None
    pid = None
    try:
        device.require_root('the hook acceptance fixture')
        artifacts = {
            'ij2art': 'out/ij2art', 'payload.so': 'out/payload.so',
            'art-api-jni.so': 'out/art-api-jni.so',
            'hookapp.dex': 'out/test-hookapp-dex/classes.dex',
            'replacement.dex': 'out/test-replacement-dex/classes.dex',
        }
        for path in artifacts.values():
            if not (lib.REPO / path).is_file():
                raise RuntimeError('missing artifact: run test/build-art-api.sh first')
        device.push(artifacts)
        # app_process appends the system's -Xusejit:true after user options.
        # dalvikvm64 lets this isolated fixture disable JIT without global props.
        fixture = lib.Fixture(device, lib.launch_command(
            device.remote + '/hookapp.dex', 'org.ij2art.test.AdmissionMain', args.mode,
            device.remote + '/art-api-jni.so', device.remote + '/payload.so',
            device.remote + '/phase'), echo=True)

        def phase(n):
            device.shell('echo ' + str(n) + ' > ' + device.remote + '/phase')

        fixture.await_line(r'FIXTURE_PID=(\d+)', fail='HOOK_TEST_FAIL')
        mode_line = fixture.await_line(r'RUNTIME_MODE=', fail='HOOK_TEST_FAIL')
        assert 'RUNTIME_MODE=' + {'jit': '1', 'no-jit': '0', 'debuggable': '3'}[args.mode] in mode_line
        ids_line = fixture.await_line(r'OPAQUE_IDS=', fail='HOOK_TEST_FAIL')
        if args.mode == 'debuggable': assert 'OPAQUE_IDS=true' in ids_line
        line = fixture.await_line(r'HOOK_FIXTURE_READY pid=(\d+)', fail='HOOK_TEST_FAIL')
        pid = re.search(r'pid=(\d+)', line).group(1)
        ctl = lib.Ctl(device, pid, '')
        caps = ctl('hook', 'init', contains='"adapter":"staticcopy-v1"')
        for expected in ('"replacement":true', '"safe_install":true',
                         '"physical_restore":false', '"delete_mode":"logical_disable"'):
            assert expected in caps, caps
        print('capabilities:', caps)

        ctl('hook', 'query', '999', ok=False, contains='status=-12')
        ctl('hook', 'del', '999', ok=False, contains='status=-12')
        dex_id = int(ctl('dex', 'upload', device.remote + '/replacement.dex', '--nonce', '881905'))
        replacement = 'fixture.Replacement.replace(Lorg/ij2art/HookContext;)Ljava/lang/Object;'
        owner = 'org.ij2art.test.AdmissionMain.'
        ctl('hook', 'add', '--dex-id', '999', '--target', owner + 'cold(I)I',
            '--replacement', replacement, ok=False, contains='status=-12')
        ctl('hook', 'add', '--dex-id', str(dex_id), '--target', owner + 'cold(I)I',
            '--replacement', 'fixture.Replacement.wrongSignature(I)Ljava/lang/Object;',
            ok=False, contains='status=-17')
        ctl('hook', 'add', '--dex-id', str(dex_id), '--target', owner + 'cold(I)J',
            '--replacement', replacement, ok=False, contains='return type mismatch')

        def add(method, ok=True, contains=None):
            return ctl('hook', 'add', '--dex-id', str(dex_id),
                       '--target', owner + method + '(I)I', '--replacement', replacement,
                       ok=ok, contains=contains)

        if args.mode != 'no-jit':
            add('cold', ok=False, contains='JIT compilation or queued work is active')
        assert not ctl('hook', 'list')
        ctl('dex', 'query', str(dex_id), contains='hook_refs=0')
        phase(4)
        fixture.await_line(r'JIT_IDLE_READY', fail='HOOK_TEST_FAIL')
        # A BUSY compiler can make a safe request transiently inadmissible.
        def settled_add(method, ok=True, contains=None):
            deadline = time.monotonic() + 15
            while True:
                result = device.shell(shlex.join([device.remote + '/ij2art', 'ctl', '--pid', pid,
                    'hook', 'add', '--dex-id', str(dex_id), '--target', owner + method + '(I)I',
                    '--replacement', replacement]), check=False)
                out = result.stdout + result.stderr
                if 'status=-18' in out and ('JIT' in out or 'visibly initialized' in out) and time.monotonic() < deadline:
                    time.sleep(0.1)
                    continue
                assert (result.returncode == 0) == ok, out
                if contains: assert contains in out, out
                print('ADMISSION:', method, out.strip(), flush=True)
                return result.stdout.strip() if ok else out

        for _ in range(2):
            settled_add('active', ok=False, contains='active managed frames')
            ctl('dex', 'query', str(dex_id), contains='hook_refs=0')
            assert not ctl('hook', 'list')
        ctl('hook', 'add', '--dex-id', str(dex_id),
            '--target', 'org.ij2art.test.AdmissionMain$Broken.cold(I)I',
            '--replacement', replacement,
            ok=False, contains='initialize target class')
        ctl('dex', 'query', str(dex_id), contains='hook_refs=0')
        lazy_id = ctl('hook', 'add', '--dex-id', str(dex_id),
            '--target', 'org.ij2art.test.AdmissionMain$Lazy.cold(I)I',
            '--replacement', replacement)
        hot_id = settled_add('hot')
        osr_id = settled_add('osr')
        pattern_id = settled_add('pattern')
        cold_id = settled_add('cold')
        ctl('dex', 'query', str(dex_id), contains='hook_refs=5')
        phase(1)
        fixture.await_line(r'ACTIVE_FRAMES_EXITED_OK', fail='HOOK_TEST_FAIL')
        active_id = settled_add('active')
        ctl('hook', 'query', cold_id, contains='ENTRY_ONLY')
        ctl('hook', 'del', cold_id, contains='state=DISABLED')
        ctl('hook', 'del', cold_id, contains='state=DISABLED')
        phase(2)
        fixture.await_line(r'LOGICAL_DISABLE_OK', fail='HOOK_TEST_FAIL')
        ctl('dex', 'query', str(dex_id), contains='hook_refs=6')
        ctl('dex', 'del', str(dex_id), ok=False, contains='status=-18')
        ctl('shutdown')
        phase(3)
        fixture.await_line(r'ALL_ADMISSION_TESTS_PASS', fail='HOOK_TEST_FAIL')
        fixture.proc.wait(timeout=15)
        assert fixture.proc.returncode == 0, 'fixture exit=' + str(fixture.proc.returncode)
        print('PASS: private JIT/OSR retirement, CHA and code GC, class initialization/failure, busy JIT/active-frame admission, callOriginal, logical disable, shutdown (CheckJNI); mode=' + args.mode)
    finally:
        if fixture and fixture.proc.poll() is None and pid:
            lib.stop_process(device, pid, ('org.ij2art.test.AdmissionMain',))
        if fixture:
            fixture.drain()
            fixture.finish(timeout=5)
        # This unique directory was created exclusively by this run.
        device.shell(shlex.join(['rm', '-rf', device.remote]), check=False)


if __name__ == '__main__':
    main()
