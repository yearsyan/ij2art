#!/usr/bin/env python3
"""Built-in observation tracer regression on a real device, in a disposable app_process.

`hook trace --target ...` must initialize the adapter, upload the embedded tracer DEX
idempotently (fixed nonce), install the hook and stay transparent to the original
result. The tracer's records (arguments, result, wall time, caller stack) must appear
in logcat under the ij2art.trace tag without dispatch-machinery frames.

Run test/build-art-api.sh first, then this script with --serial DEVICE.
"""
import re

import lib

OWNER = 'org.ij2art.test.HookUpdateCases.'
TARGET = OWNER + 'staticValue(I)I'
SYNC_TARGET = OWNER + 'syncValue(I)I'


def main():
    args = lib.arguments('jit', 'no-jit', 'debuggable')
    device = lib.Device(args, 'tracer')
    fixture = None
    pid = None
    try:
        device.require_root('the tracer fixture')
        artifacts = {'ij2art': 'out/ij2art', 'payload.so': 'out/payload.so',
                     'jni.so': 'out/art-api-jni.so',
                     'app.dex': 'out/test-hookapp-dex/classes.dex'}
        for path in artifacts.values():
            if not (lib.REPO / path).is_file():
                raise RuntimeError('missing artifact: run test/build-art-api.sh first')
        device.push(artifacts)
        fixture = lib.Fixture(device, lib.launch_command(
            device.remote + '/app.dex', 'org.ij2art.test.FixtureMain', args.mode,
            device.remote + '/jni.so', device.remote + '/payload.so', 'update'), echo=True)
        pid = fixture.await_ready(r'UPDATE_READY pid=(\d+)')
        assert pid and pid.isdigit(), 'fixture did not start'
        ctl = lib.Ctl(device, pid, '/jni.so')

        # Prepare mirrors the SDK's free s0..s3 backup slots, so it must run before any
        # hook install consumes them; hook init only publishes the SDK and is harmless.
        ctl('hook', 'init', contains='"replacement":true')
        sdk = ctl.call(lib.SDK_BACKUP, lib='/payload.so')
        ctl.expect('fixture_update_prepare', sdk)

        # One-shot path: builtin upload + hook add in a single command.
        first = ctl('hook', 'trace', '--target', TARGET, contains='replacement org.ij2art.tracer.Tracer.trace')
        hook_id = re.search(r'hook_id=(\d+)', first).group(1)
        dex_id = re.search(r'dex_id=(\d+)', first).group(1)
        assert 'ij2art.trace' in first, first
        # The fixed nonce makes repeated builtin uploads idempotent, and trace installs
        # a second target without another upload or an explicit hook init.
        again = ctl('dex', 'upload', '--builtin', 'tracer')
        assert again.strip() == dex_id, (again, dex_id)
        assert len(re.findall(r'dex_id=', ctl('dex', 'list'))) == 1
        sync = ctl('hook', 'trace', '--target', SYNC_TARGET, contains='hook_id=')
        assert re.search(r'dex_id=(\d+)', sync).group(1) == dex_id, sync

        device.shell('logcat -c')
        # Results stay identical to the unhooked fixture: the tracer only observes.
        ctl.expect('fixture_update_probe', 0, 5, 15)
        ctl.expect('fixture_update_probe', 2, 5, 15)
        if args.mode == 'no-jit':
            # dalvikvm64 loads no libandroid_runtime, so android.util.Log has no native
            # binding and the records cannot reach logcat; transparency still proves the
            # dispatch path. Real apps (zygote/app_process) always have the binding.
            ctl('hook', 'del', hook_id, contains='state=DISABLED')
            print('PASS: builtin tracer one-shot install, idempotent upload and transparent '
                  'original results (logcat unavailable under dalvikvm64); mode=' + args.mode,
                  flush=True)
            return
        log = device.shell('logcat -d --pid=' + pid + ' -s ij2art.trace:I').stdout
        # logcat repeats its header on every physical line; keep only message text so a
        # multi-line record reads as one block.
        log = '\n'.join(line.split('ij2art.trace: ', 1)[1]
                        for line in log.splitlines() if 'ij2art.trace: ' in line)
        entry = re.search(r'enter [^\n]*staticValue[^\n]*\n(?:.|\n)*?exit ', log)
        assert entry, log
        head = entry.group(0)
        assert 'arg[0]=5' in head, log
        assert 'thread=' in head, log
        assert '\n  at ' in head, 'caller stack missing: ' + log
        assert '\n  at org.ij2art.Bridge' not in head and '\n  at org.ij2art.tracer.' not in head \
            and '\n  at java.lang.reflect.' not in head, \
            'dispatch frames leaked into the stack: ' + log
        assert re.search(r'exit [^\n]*staticValue\(int\) after \d+ ms: 15', log), log
        assert re.search(r'enter [^\n]*syncValue[^\n]*\n  arg\[0\]=5', log), log
        assert re.search(r'exit [^\n]*syncValue\(int\) after \d+ ms: 15', log), log

        # hook del with nothing in flight goes straight to DISABLED.
        ctl('hook', 'del', hook_id, contains='state=DISABLED')
        print('PASS: builtin tracer one-shot install, idempotent upload, transparent '
              'original results, args/result/time/stack logcat records; mode=' + args.mode,
              flush=True)
    except BaseException:
        if fixture:
            fixture.dump()
        elif pid:
            print(device.shell('logcat -d --pid=' + pid + ' -t 150', check=False).stdout[-15000:],
                  flush=True)
        raise
    finally:
        lib.stop_process(device, pid, (device.remote, 'FixtureMain'))
        if fixture:
            fixture.finish()
        device.remove()


if __name__ == '__main__':
    main()
