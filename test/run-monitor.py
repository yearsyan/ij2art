#!/usr/bin/env python3
"""Check + multi-wrap JSON regression on a new process in an isolated directory."""
from collections import Counter
import argparse
import json
import re
import selectors
import shlex
import subprocess
import time

import lib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--calls', type=int, default=50000)
    args = parser.parse_args()
    assert args.calls >= 20000, 'need enough records to wrap the normal 8 MiB map'
    device = lib.Device(args, 'monitor')
    logs = lib.REPO / 'out' / ('monitor-validation-' + time.strftime('%Y%m%d-%H%M%S'))
    logs.mkdir(parents=True)
    fixture = monitor = None
    fixture_pid = monitor_pid = None

    def shell(command, check=True):
        return device.shell(command, check=check, timeout=20)

    try:
        shell('id').check_returncode()
        info = shell('getprop ro.product.manufacturer; getprop ro.product.model; '
                     'getprop ro.build.version.release; uname -r; getconf PAGESIZE').stdout
        (logs / 'device.txt').write_text(info)
        print(info, end='')
        device.push({'ij2art': 'out/ij2art', 'monitor-fixture': 'out/monitor-fixture'},
                    executables=('ij2art', 'monitor-fixture'))
        with (logs / 'check.txt').open('w') as log:
            for attempt in range(3):
                result = shell(shlex.join([device.remote + '/ij2art', 'monitor', '--check']), check=False)
                log.write(result.stdout + result.stderr)
                assert result.returncode == 0, result.stdout + result.stderr
                assert 'received=2048' in result.stdout and 'check passed' in result.stdout
                print(f'check {attempt + 1}/3: passed')

        fixture = subprocess.Popen(device.cmd + ['shell', device.root(shlex.join([
            device.remote + '/monitor-fixture', str(args.calls)]))], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        selector = selectors.DefaultSelector()
        selector.register(fixture.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not selector.select(timeout=0.2):
                continue
            line = fixture.stdout.readline()
            match = re.search(r'MONITOR_READY pid=(\d+)', line)
            if match:
                fixture_pid = int(match[1])
                break
            assert line, 'fixture exited before ready'
        selector.close()
        assert fixture_pid, 'fixture ready timeout'

        with (logs / 'events.jsonl').open('w') as stdout, (logs / 'monitor.txt').open('w') as stderr:
            cmd = 'echo $$ > ' + shlex.quote(device.remote + '/monitor.pid') + '; exec ' + shlex.join([
                device.remote + '/ij2art', 'monitor', '--pid', str(fixture_pid), '--secs', '60', '--json'])
            monitor = subprocess.Popen(device.cmd + ['shell', device.root(cmd)], stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 10
            while 'observing' not in (logs / 'monitor.txt').read_text():
                assert monitor.poll() is None, (logs / 'monitor.txt').read_text()
                assert time.monotonic() < deadline, 'monitor ready timeout'
                time.sleep(0.05)
            monitor_pid = int(shell('cat ' + shlex.quote(device.remote + '/monitor.pid')).stdout.strip())
            fixture.stdin.write('g\n')
            fixture.stdin.flush()
            result, _ = fixture.communicate(timeout=45)
            assert fixture.returncode == 0 and f'MONITOR_DONE calls={args.calls}' in result, result
            fixture_pid = None
            shell(shlex.join(['kill', '-INT', str(monitor_pid)]))
            monitor.wait(timeout=15)
            monitor_pid = None
            assert monitor.returncode == 0, (logs / 'monitor.txt').read_text()

        counts = Counter()
        next_marker = 0
        pending_fd = None
        phase = 0
        for line in (logs / 'events.jsonl').open():
            ev = json.loads(line)
            key = (ev['kind'], ev['nr'])
            assert key == [('sys_enter', 56), ('sys_exit', 56),
                           ('sys_enter', 57), ('sys_exit', 57)][phase], (phase, ev)
            assert ev['rd_fail'] == 0 and ev['trunc'] == 0, ev
            if phase == 0:
                assert ev['data'] == '/dev/null' and ev['args'][3] == next_marker, ev
                assert ev['pc'] and ev['pc'] != '?', ev
                next_marker += 1
            elif phase == 1:
                pending_fd = ev['ret']
                assert pending_fd >= 0, ev
            elif phase == 2:
                assert ev['args'][0] == pending_fd, ev
            else:
                assert ev['ret'] == 0, ev
            phase = (phase + 1) % 4
            counts[key] += 1
        expected = {(kind, nr): args.calls for kind in ['sys_enter', 'sys_exit'] for nr in [56, 57]}
        assert counts == expected and phase == 0, counts
        summary = (logs / 'monitor.txt').read_text()
        assert f'received={args.calls * 4}' in summary, summary
        assert f'emitted: sys_enter={args.calls * 2} sys_exit={args.calls * 2}' in summary, summary
        assert 'dropped: sys_enter=0 sys_exit=0' in summary, summary
        report = (f'PASS: checks=3 calls={args.calls} received={sum(counts.values())} '
                  f'normal_ring_wraps={args.calls * 4 * 248 // (8 * 1024 * 1024)} '
                  'duplicates=0 dropped=0\n')
        (logs / 'result.txt').write_text(report)
        print(report, end='')
        print('Logs:', logs)
    finally:
        for pid in [monitor_pid, fixture_pid]:
            if pid:
                shell(shlex.join(['kill', '-TERM', str(pid)]), check=False)
        for process in [monitor, fixture]:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        device.remove()


if __name__ == '__main__':
    main()
