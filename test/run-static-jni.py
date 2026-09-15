#!/usr/bin/env python3
"""Run a static JNI fixture in a new disposable app_process with CheckJNI.

--original selects the historical cold static target proof, which rejects other libart builds.
--logical-disable exercises production lifecycle code on declared native methods;
it performs no managed method conversion and does not certify safe installation.
Neither fixture modifies an existing App or zygote. This is not a CLI Hook test.
"""
import argparse
import lib
import re
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    fixture_mode = parser.add_mutually_exclusive_group()
    fixture_mode.add_argument('--original', action='store_true')
    fixture_mode.add_argument('--logical-disable', action='store_true')
    args = parser.parse_args()
    device = lib.Device(args, 'static')
    name = 'static-original' if args.original else 'jni-abi'
    main_class = 'org.ij2art.StaticOriginal' if args.original else 'org.ij2art.test.JniAbi'
    if args.logical_disable:
        name, main_class = 'logical-disable', 'org.ij2art.LogicalDisable'
    artifacts = {'fixture.so': 'out/' + name + '.so',
                 'fixture.dex': 'out/' + name + '-dex/classes.dex'}
    for path in artifacts.values():
        if not (lib.REPO / path).is_file():
            raise RuntimeError('run zsh test/build-' + name + '.sh first')

    proc = None
    output = ''
    try:
        device.raw('shell', 'mkdir', device.remote)
        for dest, source in artifacts.items():
            device.raw('push', str(lib.REPO / source), device.remote + '/' + dest)
        command = 'echo IJ2ART_FIXTURE_PID=$$\nexec env ' + shlex.join([
            'CLASSPATH=' + device.remote + '/fixture.dex', 'app_process', '-Xcheck:jni', '/',
            main_class, device.remote + '/fixture.so'])
        proc = subprocess.Popen(device.cmd + ['shell', device.root(command)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            output, _ = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired as error:
            output = error.output or ''
            if isinstance(output, bytes):
                output = output.decode(errors='replace')
            raise RuntimeError('isolated fixture timeout') from error
        print(output.rstrip())
        if proc.returncode != 0 or 'PASS:' not in output or 'JNI DETECTED ERROR' in output:
            raise RuntimeError('fixture failed: exit ' + str(proc.returncode))
    finally:
        match = re.search(r'IJ2ART_FIXTURE_PID=(\d+)', output)
        if match:
            lib.stop_process(device, match.group(1),
                             (device.remote + '/fixture.so', main_class))
        if proc and proc.poll() is None:
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.communicate(timeout=3)
        device.remove()


if __name__ == '__main__':
    main()
