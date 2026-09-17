#!/usr/bin/env python3
"""Scaffold and compile ij2art ART-hook replacement DEX projects.

The ij2art CLI runs on the Android device, but a replacement DEX must be compiled
on a host with a JDK (javac/jar) and the Android SDK (platform android.jar and
build-tools d8). This script owns that toolchain so an agent never has to
assemble the javac/d8 command lines by hand:

  init   create src/<package>/<Class>.java with the HookContext contract
         documented in comments, plus hookproj.json
  build  compile every src/**/*.java into a standalone replacement DEX and
         print the exact ctl commands to upload and install it

Toolchain resolution order (first hit wins):
  JDK:        --jdk DIR | JAVA_HOME | javac/jar on PATH
  SDK:        --sdk DIR | ANDROID_HOME / ANDROID_SDK_ROOT | ~/Library/Android/sdk,
              ~/Android/sdk, ~/android-sdk (first with a platforms/ dir)
  build-tools:--build-tools DIR | highest version under <sdk>/build-tools
  platform:   --platform android-36 | --platform /path/android.jar | highest
              version under <sdk>/platforms
  hook API:   --hook-api JAR | <repo>/out/ij2art-hook-api.jar | ./ij2art-hook-api.jar

Exit codes mirror the ij2art CLI: 0 success, 1 runtime error, 2 usage error.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANIFEST = 'hookproj.json'
SIGNATURE = '(Lorg/ij2art/HookContext;)Ljava/lang/Object;'
CLASS_RE = re.compile(r'^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+$')
METHOD_RE = re.compile(r'^[A-Za-z_$][\w$]*$')

TEMPLATE = '''package {package};

import android.util.Log;

import org.ij2art.HookContext;

/**
 * ij2art ART-hook replacement. The install command is:
 *
 *   ij2art ctl --pid PID hook add --dex-id DEX_ID \\
 *       --target 'com.target.Class.method(I)Ljava/lang/String;' \\
 *       --replacement '{binary}.{method}(Lorg/ij2art/HookContext;)Ljava/lang/Object;'
 *
 * The replacement method MUST be `public static Object name(org.ij2art.HookContext)`
 * and live inside the uploaded DEX (it is resolved against that DEX's own
 * InMemoryDexClassLoader). Constructors cannot be replacements.
 *
 * HookContext contract (see out/ij2art-hook-api.jar):
 *   ctx.executable   the hooked Method or Constructor (reflection object).
 *   ctx.method / ctx.constructor
 *                    the same target; exactly one is non-null.
 *   ctx.thisObject   receiver for instance methods; for constructor targets the
 *                    already-allocated object being initialized; null for static.
 *   ctx.args         boxed arguments; primitives arrive as their wrapper types.
 *   ctx.callOriginal()
 *                    runs the original implementation with ctx.args and returns its
 *                    (boxed) result. For a constructor it initializes ctx.thisObject
 *                    in place and returns null; it never allocates a second object.
 *   ctx.callOriginal(newArgs)
 *                    same, with replacement arguments (count/types must match).
 *
 * Semantics to keep in mind:
 *   - The context is confined to the calling thread and this invocation; do not
 *     store it. A `hook update` does not invalidate an in-flight invocation.
 *   - For a synchronized target, ART holds the receiver/declaring-class monitor
 *     around the ENTIRE replacement, including callOriginal -- keep it fast.
 *   - The return value must match the target's return type (boxed); for void and
 *     constructor targets return null. Throwing propagates to the original caller.
 *   - Coverage is ENTRY_ONLY: callers that already inlined the target bypass the
 *     hook. A hook that "never fires" on a hot path is usually this, not a bug.
 *   - This DEX is loaded with parent-first delegation, so android.* and
 *     org.ij2art.HookContext resolve from the app/SDK loaders -- do not bundle
 *     the Hook SDK classes into the output (the build script already keeps them
 *     on the compile-only classpath).
 */
public final class {className} {{
    private static final String TAG = "{tag}";

    private {className}() {{}}

    public static Object {method}(HookContext ctx) throws Throwable {{
        Log.i(TAG, "enter " + ctx.executable + " args="
                + java.util.Arrays.deepToString(ctx.args));
        Object result = ctx.callOriginal();
        Log.i(TAG, "exit " + ctx.executable + " -> " + result);
        return result;
    }}
}}
'''


def fail(message):
    raise RuntimeError(message)


def find_binary(directory, name):
    candidate = directory / 'bin' / name
    if directory and candidate.is_file():
        return str(candidate)
    found = shutil.which(name)
    return found


def resolve_jdk(flag):
    """Return (javac, jar) from --jdk, JAVA_HOME or PATH."""
    home = Path(flag).expanduser() if flag else (
        Path(os.environ['JAVA_HOME']).expanduser() if os.environ.get('JAVA_HOME') else None)
    if home:
        javac, jar = find_binary(home, 'javac'), find_binary(home, 'jar')
        if not javac or not jar:
            fail(f'JDK at {home} has no bin/javac and bin/jar')
        return javac, jar
    javac, jar = shutil.which('javac'), shutil.which('jar')
    if not javac or not jar:
        fail('no JDK found: pass --jdk DIR, set JAVA_HOME, or put javac/jar on PATH')
    return javac, jar


def resolve_sdk(flag):
    if flag:
        sdk = Path(flag).expanduser()
    else:
        for env in ('ANDROID_HOME', 'ANDROID_SDK_ROOT'):
            if os.environ.get(env):
                sdk = Path(os.environ[env]).expanduser()
                break
        else:
            usable = lambda p: (p / 'platforms').is_dir()
            sdk = next((p for p in (Path('~/Library/Android/sdk').expanduser(),
                                    Path('~/Android/sdk').expanduser(),
                                    Path('~/android-sdk').expanduser()) if usable(p)), None)
            if sdk is None:
                fail('no Android SDK found: pass --sdk DIR or set ANDROID_HOME')
    if not sdk.is_dir():
        fail(f'Android SDK directory does not exist: {sdk}')
    return sdk


def version_key(path):
    return [int(part) if part.isdigit() else -1 for part in re.split(r'[.-]', path.name)]


def resolve_build_tools(sdk, flag):
    root = Path(flag).expanduser() if flag else sdk / 'build-tools'
    if (root / 'd8').is_file():
        return str(root / 'd8')
    if root.is_dir():
        versions = sorted((p for p in root.iterdir() if (p / 'd8').is_file()),
                          key=version_key, reverse=True)
        if versions:
            return str(versions[0] / 'd8')
    fail(f'no d8 found: pass --build-tools DIR or install SDK build-tools under {sdk}/build-tools')


def resolve_platform(sdk, flag):
    if flag:
        given = Path(flag).expanduser()
        if given.is_file():
            return str(given)
        candidate = given if given.is_dir() else sdk / 'platforms' / flag
        if (candidate / 'android.jar').is_file():
            return str(candidate / 'android.jar')
        fail(f'--platform {flag}: no android.jar found')
    root = sdk / 'platforms'
    versions = sorted((p for p in root.iterdir() if (p / 'android.jar').is_file()),
                      key=version_key, reverse=True) if root.is_dir() else []
    if not versions:
        fail(f'no SDK platform with android.jar under {root}: pass --platform')
    return str(versions[0] / 'android.jar')


def resolve_hook_api(flag):
    for candidate in ([Path(flag).expanduser()] if flag else
                      [REPO / 'out' / 'ij2art-hook-api.jar', Path('ij2art-hook-api.jar')]):
        if candidate.is_file():
            return str(candidate)
    fail('no ij2art-hook-api.jar found: pass --hook-api JAR or run ./build.sh first')


def read_manifest(project):
    path = project / MANIFEST
    if not path.is_file():
        fail(f'{path} missing: run init first, or pass --class/--method')
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        fail(f'{path}: invalid JSON: {e}')
    if not CLASS_RE.match(data.get('class', '')) or not METHOD_RE.match(data.get('method', '')):
        fail(f'{path}: invalid class/method names')
    return data['class'], data['method']


def cmd_init(args):
    if not CLASS_RE.match(args.class_name):
        fail(f'--class must be a qualified Java class name, got: {args.class_name}')
    if not METHOD_RE.match(args.method):
        fail(f'--method must be a Java identifier, got: {args.method}')
    project = Path(args.directory)
    package, class_name = args.class_name.rsplit('.', 1)
    source = project / 'src' / Path(*package.split('.')) / (class_name + '.java')
    if source.exists() and not args.force:
        fail(f'{source} already exists (use --force to overwrite)')
    source.parent.mkdir(parents=True, exist_ok=True)
    tag = 'ij2art.' + class_name[:16]
    source.write_text(TEMPLATE.format(package=package, className=class_name,
                                      binary=args.class_name, method=args.method, tag=tag))
    (project / MANIFEST).write_text(json.dumps(
        {'class': args.class_name, 'method': args.method}, indent=2) + '\n')
    emit(args, {'project': str(project), 'source': str(source),
                'next': f'python3 {Path(__file__).name} build {project}'})


def cmd_build(args):
    project = Path(args.directory)
    class_name, method = read_manifest(project)
    if args.class_name:
        class_name = args.class_name
    if args.method:
        method = args.method
    sources = sorted((project / 'src').rglob('*.java'))
    if not sources:
        fail(f'no .java sources under {project}/src')
    javac, jar = resolve_jdk(args.jdk)
    sdk = resolve_sdk(args.sdk)
    d8 = resolve_build_tools(sdk, args.build_tools)
    android_jar = resolve_platform(sdk, args.platform)
    hook_api = resolve_hook_api(args.hook_api)
    out_dex = Path(args.output) if args.output else project / 'out' / 'replacement.dex'
    with tempfile.TemporaryDirectory(prefix='hookproj-') as tmp:
        classes = Path(tmp) / 'classes'
        classes.mkdir()
        run([javac, '--release', '8', '-Xlint:-options',
             '-cp', os.pathsep.join([hook_api, android_jar]),
             '-d', str(classes)] + [str(s) for s in sources])
        archive = Path(tmp) / 'replacement.jar'
        run([jar, 'cf', str(archive), '-C', str(classes), '.'])
        dex_dir = Path(tmp) / 'dex'
        dex_dir.mkdir()
        run([d8, '--min-api', '31', '--lib', android_jar,
             '--classpath', hook_api, '--output', str(dex_dir), str(archive)])
        out_dex.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(dex_dir / 'classes.dex', out_dex)
    replacement = f'{class_name}.{method}{SIGNATURE}'
    remote = f'/data/local/tmp/{out_dex.name}'
    commands = [
        f'adb push {out_dex} {remote}',
        f'ij2art ctl --pid PID dex upload {remote}',
        "ij2art ctl --pid PID hook add --dex-id DEX_ID "
        f"--target 'com.target.Class.method(I)V' --replacement '{replacement}'",
    ]
    emit(args, {'dex': str(out_dex), 'replacement': replacement, 'commands': commands})


def run(command):
    print('+', ' '.join(command), file=sys.stderr)
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        fail(f'command failed with exit {e.returncode}: {command[0]}')
    except FileNotFoundError:
        fail(f'tool not found: {command[0]}')


def emit(args, data):
    if getattr(args, 'json', False):
        print(json.dumps({'ok': True, 'data': data}))
    else:
        for key, value in data.items():
            if isinstance(value, list):
                print(f'{key}:')
                for line in value:
                    print(' ', line)
            else:
                print(f'{key}: {value}')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='action', required=True)
    for name, handler in (('init', cmd_init), ('build', cmd_build)):
        p = sub.add_parser(name)
        p.add_argument('directory', help='project directory')
        p.add_argument('--json', action='store_true', help='print a machine-readable envelope')
        p.set_defaults(handler=handler)
    sub.choices['init'].add_argument('--class', dest='class_name',
                                     default='com.example.hooks.SampleHook',
                                     help='qualified replacement class name')
    sub.choices['init'].add_argument('--method', default='onHook',
                                     help='replacement method name')
    sub.choices['init'].add_argument('--force', action='store_true')
    build = sub.choices['build']
    build.add_argument('--jdk', help='JDK home (default: JAVA_HOME or PATH)')
    build.add_argument('--sdk', help='Android SDK root (default: ANDROID_HOME or common paths)')
    build.add_argument('--build-tools', help='build-tools directory containing d8')
    build.add_argument('--platform', help='android-36, a platforms dir, or an android.jar path')
    build.add_argument('--hook-api', help='path to ij2art-hook-api.jar')
    build.add_argument('--class', dest='class_name', help='override manifest class')
    build.add_argument('--method', help='override manifest method')
    build.add_argument('-o', '--output', help='output .dex path')
    args = parser.parse_args()
    try:
        args.handler(args)
    except RuntimeError as e:
        if getattr(args, 'json', False):
            print(json.dumps({'ok': False, 'error': {'code': None, 'message': str(e)}}))
        else:
            print(f'error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
