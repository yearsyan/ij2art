#!/usr/bin/env python3
"""Shared harness for the test/run-*.py on-device regressions.

Device wraps adb/root/shell and artifact pushing, Fixture wraps a long-lived
app_process/dalvikvm fixture with an output pump and READY waiting, and Ctl
wraps the control-ring CLI (call/expect and the hook-add BUSY retry). Each
script keeps only its own constants and assertion sequence. The --serial/
--adb/--mode interfaces and the condition of every assertion are preserved
verbatim from the pre-refactor implementations. stdout density is not part of
the contract: scripts with echo=False do not echo fixture lines while running,
and failures are replayed through drain()/dump().
"""
import argparse
from adb_root import root_command
import pathlib
import queue
import re
import shlex
import subprocess
import threading
import time
import uuid

REPO = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = 'org.ij2art.aottest'
APK_ACTIVITY = 'org.ij2art.apktest.MainActivity'
FLAG = '/data/local/tmp/ij2art-aottest-selfload'
SDK_BACKUP = '_ZN8ij2art6artint10sdk_backupEv'
MODES = ('jit', 'no-jit', 'debuggable', 'aot')


def arguments(*modes):
    """Common arguments for every script; passing modes adds --mode (defaults to the first)."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    if modes:
        parser.add_argument('--mode', choices=modes, default=modes[0])
    return parser.parse_args()


class Device:
    """adb -s SERIAL + root wrapper + shell/raw + a unique remote directory and artifact push."""

    def __init__(self, args, tag):
        self.cmd = [args.adb, '-s', args.serial]
        self.root = root_command(self.cmd)
        self.remote = '/data/local/tmp/ij2art-' + tag + '-' + uuid.uuid4().hex[:12]

    def shell(self, command, check=True, timeout=60):
        return subprocess.run(self.cmd + ['shell', self.root(command)], check=check,
                              capture_output=True, text=True, timeout=timeout)

    def raw(self, *words, check=True, timeout=60):
        return subprocess.run(self.cmd + list(words), check=check,
                              capture_output=True, text=True, timeout=timeout)

    def require_root(self, why=None):
        assert 'uid=0' in self.shell('id', timeout=30).stdout, \
            'root is required for ' + why if why else 'uid=0 required'

    def push(self, artifacts, executables=('ij2art',)):
        """Push out/ artifacts into the unique remote directory; fail on a missing build."""
        self.raw('shell', 'mkdir', self.remote)
        for name, path in artifacts.items():
            if not (REPO / path).is_file():
                raise RuntimeError('missing artifact: ' + path)
            self.raw('push', str(REPO / path), self.remote + '/' + name)
        for name in executables:
            self.shell('chmod 755 ' + self.remote + '/' + name)

    def remove(self):
        self.raw('shell', 'rm', '-rf', self.remote, check=False)


def launch_command(classpath, main_class, mode, *extra):
    """The three launch shapes: jit/app_process, no-jit/dalvikvm64, debuggable/opaque-ids."""
    options = (['-Xcompiler-option', '--debuggable', '-Xopaque-jni-ids:indices']
               if mode == 'debuggable' else [])
    argv = (['dalvikvm64', '-Xcheck:jni', '-Xusejit:false', '-cp', classpath]
            if mode == 'no-jit' else ['app_process', '-Xcheck:jni', *options, '/'])
    return 'CLASSPATH=' + shlex.quote(classpath) + ' ' + shlex.join([*argv, main_class, *extra])


class Fixture:
    """Long-lived fixture subprocess: a pump thread collects every output line and
    supports READY/line waits plus failure replay."""

    def __init__(self, device, command, echo=False):
        self.device = device
        self.echo = echo
        self.proc = subprocess.Popen(device.cmd + ['shell', device.root(command)],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.history = []
        self.lines = queue.Queue()
        self.pid = None
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        # Reader thread plus queue. A buffered readline cannot be used together with select:
        # when two lines arrive at once they stay in the python buffer while the fd has no
        # more data, so select never returns. This has actually happened.
        for line in self.proc.stdout:
            self.history.append(line)
            if self.echo:
                print(line.rstrip(), flush=True)
            self.lines.put(line)
        self.lines.put(None)

    def await_ready(self, pattern, timeout=30):
        """Block until a READY line appears and record the pid; assert if the fixture exits."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self.lines.get(timeout=max(0.1, deadline - time.monotonic()))
            assert line, 'fixture exited before startup'
            match = re.search(pattern, line)
            if match:
                self.pid = match.group(1)
                return self.pid
        raise AssertionError('fixture startup timeout')

    def await_line(self, pattern, timeout=90, fail=None):
        """Phase-file protocol: wait line by line for pattern; a fail substring means failure."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                raise RuntimeError('fixture closed output while waiting for ' + pattern)
            if fail and fail in line:
                raise RuntimeError('fixture reported failure: ' + line.rstrip())
            match = re.search(pattern, line)
            if match:
                return line
        raise RuntimeError('timeout waiting for ' + pattern)

    def drain(self):
        while not self.lines.empty():
            line = self.lines.get_nowait()
            if line:
                print(line.rstrip(), flush=True)

    def dump(self, limit=150):
        """Failure path: replay queued lines and the logcat tail."""
        self.drain()
        if self.pid:
            print(self.device.shell(
                'logcat -d --pid=' + self.pid + ' -t ' + str(limit), check=False).stdout[-15000:],
                flush=True)

    def finish(self, timeout=10):
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(timeout=timeout)


def stop_process(device, pid, *alternatives):
    """TERM only after verifying the /proc/PID/cmdline identity; any one alternative group
    matching (all hints within it) is sufficient, so a recycled PID is never killed."""
    if not pid:
        return
    identity = device.shell('cat /proc/' + str(pid) + '/cmdline', check=False).stdout
    if any(all(hint in identity for hint in group) for group in alternatives):
        device.shell('kill -TERM ' + str(pid), check=False)


def apk_install(device, name='app.apk', compile_mode='speed'):
    """Install the test APK; compile_mode=None skips dexopt (the plain-App java-calls case)."""
    device.shell('am force-stop ' + PACKAGE)
    result = device.shell('pm install -r ' + device.remote + '/' + name, timeout=120)
    assert 'Success' in result.stdout, result.stdout + result.stderr
    if compile_mode:
        result = device.shell('pm compile -m %s -f %s' % (compile_mode, PACKAGE), timeout=300)
        assert 'Success' in result.stdout, result.stdout + result.stderr


def apk_launch(device):
    """touch FLAG + am start + poll for the SELFLOAD line; returns the pid ('' on failure)."""
    device.shell('touch ' + FLAG)
    device.shell('am start -n ' + PACKAGE + '/' + APK_ACTIVITY)
    for _ in range(100):
        pid = device.shell('pidof ' + PACKAGE, check=False).stdout.strip()
        if pid and 'SELFLOAD payload started' in device.raw(
                'shell', 'logcat', '-d', '--pid=' + pid, '-s', 'ij2art.apktest:I').stdout:
            return pid
        time.sleep(0.1)
    return ''


def apk_cleanup(device, reset=True):
    device.shell('am force-stop ' + PACKAGE, check=False)
    device.shell('rm -f ' + FLAG, check=False)
    if reset:
        device.shell('pm compile --reset ' + PACKAGE, check=False, timeout=300)


class Ctl:
    """Control-ring CLI: asserts the exit code and substrings; call parses the '= 0x...'
    return value. On ok=False the return value is still stdout (a --json envelope must stay
    json.loads-able); contains checks the combined stdout+stderr text."""

    def __init__(self, device, pid, native_lib):
        self.device = device
        self.pid = pid
        self.native_lib = native_lib

    def __call__(self, *words, ok=True, contains=None):
        result = self.device.shell(shlex.join(
            [self.device.remote + '/ij2art', 'ctl', '--pid', str(self.pid),
             *map(str, words)]), check=False)
        text = result.stdout + result.stderr
        assert (result.returncode == 0) == ok, text
        if contains:
            assert contains in text, text
        return result.stdout.strip()

    def call(self, name, *values, lib=None):
        text = self('call', '--in', lib or self.native_lib, name,
                    *(hex(v & ((1 << 64) - 1)) for v in values))
        return int(re.search(r'= (0x[0-9a-f]+)', text).group(1), 16)

    def expect(self, name, *values, lib=None):
        result = self.call(name, *values, lib=lib)
        assert result == 1, '%s(%s) returned %s' % (name, values, result)

    def add_hook(self, dex, target, replacement, deadline=30, sleep=0.1):
        """hook add with a status=-18 (BUSY) retry; returns the hook_id on success."""
        end = time.monotonic() + deadline
        while True:
            result = self.device.shell(shlex.join([
                self.device.remote + '/ij2art', 'ctl', '--pid', str(self.pid),
                'hook', 'add', '--dex-id', dex, '--target', target,
                '--replacement', replacement]), check=False)
            text = result.stdout + result.stderr
            if result.returncode == 0:
                return result.stdout.strip()
            if 'status=-18' not in text or time.monotonic() >= end:
                raise AssertionError(text)
            time.sleep(sleep)
