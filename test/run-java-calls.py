#!/usr/bin/env python3
"""JSON method invocation on real ART/main Looper; no Hook adapter/init is used.

Build ./build.sh and test/build-java-calls.sh. --apk additionally needs a signed
test/build-apk.sh --aot fixture (out/aot-apktest-aligned-signed.apk).
"""
import argparse
import json
import shlex
import time

import lib

OWNER = 'org.ij2art.test.JavaCallCases'
HELPER = 'fixture.JavaCallHelper'


def arg(kind, value):
    return {'type': kind, 'value': value}


def call(method, *args, owner=OWNER, **extra):
    return {'class': owner, 'method': method, 'args': list(args), **extra}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--no-main', action='store_true')
    parser.add_argument('--apk', action='store_true')
    opts = parser.parse_args()
    assert not (opts.no_main and opts.apk)
    device = lib.Device(opts, 'java')
    fixture = None
    pid = None
    try:
        artifacts = {'ij2art': 'out/ij2art', 'helper.dex': 'out/java-call-helper-dex/classes.dex'}
        if opts.apk:
            artifacts['app.apk'] = 'out/aot-apktest-aligned-signed.apk'
        else:
            artifacts.update({'app.dex': 'out/java-call-app-dex/classes.dex',
                              'jni.so': 'out/art-api-jni.so', 'payload.so': 'out/payload.so'})
        device.push(artifacts)
        if opts.apk:
            # A plain App run: install without dexopt, the WebView check needs runtime only.
            lib.apk_install(device, compile_mode=None)
            pid = lib.apk_launch(device)
        else:
            fixture = lib.Fixture(device, lib.launch_command(
                device.remote + '/app.dex', 'org.ij2art.test.JavaCallMain', 'jit',
                device.remote + '/jni.so', device.remote + '/payload.so',
                'no-main' if opts.no_main else 'main'))
            pid = fixture.await_ready(r'JAVA_READY pid=(\d+)')
        assert pid and pid.isdigit(), 'fixture did not start'

        def fixture_output():
            if fixture:
                return ''.join(fixture.history)
            return device.shell('logcat -d --pid=' + pid, check=False).stdout

        def ctl(*words, ok=True, contains=None):
            result = device.shell(shlex.join(
                [device.remote + '/ij2art', 'ctl', '--pid', pid, '--json', *map(str, words)]),
                check=False)
            assert (result.returncode == 0) == ok, result.stdout + result.stderr + fixture_output()
            value = json.loads(result.stdout)
            assert value['ok'] == ok, value
            if contains:
                assert contains in result.stdout, result.stdout
            return value['data'] if ok else value['error']

        def submit(calls, thread='new', dex=None, ok=True, contains=None):
            words = ['java', 'call', '--thread', thread, '--request', json.dumps({'calls': calls}, ensure_ascii=False)]
            if dex is not None:
                words += ['--dex-id', str(dex)]
            return ctl(*words, ok=ok, contains=contains)

        def wait(job, expected='SUCCEEDED', delete=True):
            deadline = time.monotonic() + 20
            while job['state'] in ('QUEUED', 'RUNNING'):
                assert time.monotonic() < deadline, job
                time.sleep(0.03)
                job = ctl('java', 'query', job['id'])
            assert job['state'] == expected, job
            if delete:
                ctl('java', 'del', job['id'])
            return job

        def run(calls, **kwargs):
            expected = kwargs.pop('expected', 'SUCCEEDED')
            return wait(submit(calls, **kwargs), expected)

        def value(method, *args, **kwargs):
            return run([call(method, *args)], **kwargs)['results'][0]['value']

        assert not ctl('hook', 'list')['records'], 'executor must not install ART hooks'
        assert value('onMain') is False
        if opts.no_main:
            submit([call('onMain')], thread='main', ok=False, contains='main Looper is not ready')
            ctl('shutdown')
            print('PASS: new thread works without a main Looper; main request rejected without a job', flush=True)
            return

        assert value('onMain', thread='main') is True
        assert value('threadName').startswith('ij2art-java-')
        assert value('contextLoader') == 'dalvik.system.InMemoryDexClassLoader'
        run([call('checkRestoredLater')], thread='main')
        assert value('restoredMainLoader') is True
        run([call('checkRestoredLater'), call('fail')], thread='main', expected='FAILED')
        assert value('restoredMainLoader') is True
        assert value('pick', arg('int', 7)) == 'int:7'
        assert value('pick', arg('long', 7)) == 'long:7'
        assert value('longValue', arg('long', '9223372036854775807')) == '9223372036854775807'
        assert value('longValue', arg('long', -9223372036854775808)) == '-9223372036854775808'
        assert value('primitives', arg('boolean', True), arg('byte', -128), arg('short', 32767),
                     arg('char', '中'), arg('int', -2147483648), arg('long', '9007199254740993'),
                     arg('float', 1.25), arg('double', -0.5)) == 'true:-128:32767:中:-2147483648:9007199254740993:1.25:-0.5'
        assert value('matrix', arg('int[][]', [[1, 2], [3, 4]])) == 5
        assert value('join', arg('java.lang.String[]', ['中文', '🌏'])) == '中文:🌏'
        assert value('text', arg('java.lang.String', '中\x00文🌏')) == '中\x00文🌏'
        assert value('nullString', arg('java.lang.String', None)) == 'null'
        assert value('secret') == 'private-ok'
        assert run([call('doubleToRawLongBits', arg('double', -0.0), owner='java.lang.Double')])['results'][0]['value'] == '-9223372036854775808'
        for bad in [call('pick', arg('int', 2147483648)), call('pick', arg('int', 1.5)),
                    call('pick', arg('int', None)), call('pick', arg('boolean', 'true')),
                    call('pick', arg('double', 1e300)), call('missing'), call('fail'), call('badMessage')]:
            run([bad], expected='FAILED', thread='main')
        partial = run([call('increment'), call('fail'), call('increment')], expected='FAILED')
        assert len(partial['results']) == 1 and partial['error']['index'] == 1, partial
        assert partial['error']['type'] == 'java.lang.IllegalStateException', partial
        assert '中文 🌏' in partial['error']['message'], partial
        assert value('count') == 1
        before = len(ctl('java', 'list')['records'])
        malformed = ["{'calls':[]}", '{"calls":[]} trailing', '{"calls":[],"calls":[]}',
                     '{"calls":[]}', '{"calls":[/* comment */]}', '{"calls":[{"class":"a.B","method":"<init>"}]}',
                     json.dumps({'calls': [call('increment'), {**call('count'), 'typo': True}]}),
                     json.dumps({'calls': [call('count', receiver={'ref': 'missing'})]}),
                     json.dumps({'calls': [call('count', save='x'), call('count', save='x')]})]
        string_request = json.dumps({'calls': [call('text', arg('java.lang.String', 'literal'))]})
        malformed += [string_request.replace('"literal"', replacement) for replacement in
                      ['"raw\nnewline"', '"\\q"', '"\\u+001"']]
        malformed += ['\ufeff' + string_request, string_request + '\f',
                      string_request.replace('"literal"', 'truE'),
                      string_request.replace('"literal"', 'NULL')]
        for text in malformed:
            ctl('java', 'call', '--thread', 'new', '--request', text, ok=False)
        assert len(ctl('java', 'list')['records']) == before
        assert value('count') == 1, 'schema rejection must happen before submitting any calls'
        assert run([call('getDefault', owner='java.util.Locale', save='l'),
                    call('getLanguage', owner='java.util.Locale', receiver={'ref': 'l'})])['state'] == 'SUCCEEDED'

        dex = ctl('dex', 'upload', device.remote + '/helper.dex')['id']
        result = run([call('initializedOnMain', owner=HELPER), call('ownContextLoader', owner=HELPER),
                      call('create', arg('java.lang.String', 'prefix:'), owner=HELPER, save='obj'),
                      call('append', arg('java.lang.String', '🌏'), owner=HELPER, receiver={'ref': 'obj'}),
                      call('reference', arg('java.lang.Object', {'ref': 'obj'}))], thread='main', dex=dex)
        assert [r.get('value') for r in result['results']] == [True, True, None, 'prefix:🌏', HELPER], result
        assert result['results'][2]['opaque'] is True
        assert run([call('ownContextLoader', owner=HELPER)], dex=dex)['results'][0]['value'] is True
        run([call('ownContextLoader', owner=HELPER)], expected='FAILED')
        run([call('create', arg('java.lang.String', 'x'), owner=HELPER, save='obj'),
             call('onMain', receiver={'ref': 'obj'})], dex=dex, expected='FAILED')
        huge = run([call('huge') for _ in range(32)])
        assert huge['results_truncated'] and any(r.get('omitted') for r in huge['results']), huge
        assert huge['results'][0]['truncated'], huge

        # Full registry retains finished snapshots, never silently replays/evicts them.
        kept = [wait(submit([call('count')]), delete=False)['id'] for _ in range(16)]
        submit([call('increment')], ok=False, contains='16 Java job slots occupied')
        assert len(ctl('java', 'list')['records']) == 16
        for job_id in kept:
            ctl('java', 'del', job_id)
        assert value('count') == 1

        # CLI --file and existing batch path both carry JSON method requests.
        request_file = device.remote + '/calls.json'
        request_text = json.dumps({'calls': [call('onMain')]})
        device.shell('printf %s ' + shlex.quote(request_text) + ' > ' + request_file)
        assert wait(ctl('java', 'call', '--thread', 'main', '--file', request_file))['results'][0]['value'] is True
        batch_text = json.dumps(['java', 'call', '--thread', 'new', '--request', request_text])
        batch = device.shell('printf %s ' + shlex.quote(batch_text + '\n') + ' | ' + shlex.join([
            device.remote + '/ij2art', 'ctl', '--pid', pid, 'batch']))
        assert wait(json.loads(batch.stdout)['data'])['results'][0]['value'] is False

        if opts.apk:
            # Public real WebView API in an ordinary App UID, with a visible debugging endpoint.
            run([call('setWebContentsDebuggingEnabled', arg('boolean', True), owner='android.webkit.WebView')], thread='main')
            assert ('webview_devtools_remote_' + pid) in device.shell('cat /proc/net/unix').stdout
            run([call('setWebContentsDebuggingEnabled', arg('boolean', False), owner='android.webkit.WebView')], thread='main')
            assert ('webview_devtools_remote_' + pid) not in device.shell('cat /proc/net/unix').stdout
            print('PASS: real App WebView debugging enabled/disabled; devtools socket verified', flush=True)

        queued_dex = ctl('dex', 'upload', device.remote + '/helper.dex')['id']
        release = device.remote + '/release'
        blocked = submit([call('waitForFile', arg('java.lang.String', release), owner=HELPER)], thread='main', dex=dex)
        for _ in range(100):
            blocked = ctl('java', 'query', blocked['id'])
            if blocked['state'] == 'RUNNING':
                break
            time.sleep(0.02)
        assert blocked['state'] == 'RUNNING', blocked
        ctl('java', 'del', blocked['id'], ok=False, contains='queued/running')
        assert ctl('dex', 'del', dex, ok=False, contains='Java call')['code'] == -18
        queued = submit([call('ownContextLoader', owner=HELPER)], thread='main', dex=queued_dex)
        assert queued['state'] == 'QUEUED', queued
        assert ctl('dex', 'del', queued_dex, ok=False, contains='Java call')['code'] == -18
        assert value('onMain') is False, 'new thread and control ring remain responsive while main is blocked'
        ctl('ping')
        assert ctl('shutdown', ok=False, contains='Java calls')['code'] == -18
        assert submit([call('count')], ok=False, contains='closing')['code'] == -13
        device.shell('touch ' + release)
        wait(blocked, delete=False)
        assert wait(queued, delete=False)['results'][0]['value'] is True
        # Completed records retain only JSON; deleting the DEX does not invalidate snapshots.
        ctl('dex', 'del', dex)
        ctl('dex', 'del', queued_dex)
        assert ctl('java', 'query', blocked['id'])['state'] == 'SUCCEEDED'
        ctl('java', 'del', blocked['id'])
        ctl('java', 'del', queued['id'])
        ctl('shutdown')
        output = fixture_output()
        assert 'JNI DETECTED ERROR' not in output, output
        print('PASS: typed JSON, overloads, refs, UTF-8, errors, main/new dispatch, class initialization, '
              'loader restoration/isolation, bounded jobs/results, DEX pins and draining shutdown', flush=True)
    except BaseException:
        if fixture:
            fixture.drain()
        raise
    finally:
        if opts.apk:
            lib.apk_cleanup(device, reset=False)
        elif pid and pid.isdigit():
            lib.stop_process(device, pid, (device.remote, 'JavaCallMain'))
        if fixture:
            fixture.finish(timeout=5)
        device.remove()


if __name__ == '__main__':
    main()
