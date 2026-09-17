# Android 17 compatibility and device verification

*Chinese: [android17_zh.md](android17_zh.md)*

> Historical report of the initial exact-build adaptation. ART replacement has since migrated to [dynamic compatibility](art-compatibility.md); the allowlist and per-build RVA selection described below are no longer used. The original measurements remain as audit evidence.

Validated on 2026-09-17 using the connected rooted Pixel 7. ART replacement is
enabled for the exact build below; an Android version number alone does not
select this profile.

| Item | Verified value |
| --- | --- |
| Device / ABI | Google Pixel 7 (`panther`), arm64 |
| Android | 17, API 37, `CP41.260814.003.A2` |
| Fingerprint | `google/panther_beta/panther:17/CP41.260814.003.A2/16182618:user/release-keys` |
| ART GNU build ID | `4259bc018250195dc006f2b6cf330eb1` |
| Kernel | `6.12.81-android16-6-g86553c53da31-ab15878525-4k` |
| Page size / SELinux | 4096 bytes / Enforcing throughout |
| Build tools | NDK 28.1.13356709, build-tools 36.0.0, JDK 17 |

## Changes

- Added `android17-arm64-zombie-code`, with exact symbol RVAs, instruction
  prologues, object layouts and 412 permanent SmallPatternMatcher entry RVAs.
  Unknown ART build IDs still refuse replacement; there is no API-level fallback.
- Expanded StackVisitor storage to `0x208`, and selected the new WalkStack
  template signature. Android 14/16 profiles keep their original layouts.
- Adjusted fixture compilation requests for Android 17's extra fast tier:
  OSR/baseline/optimized are `0/2/3`. The inlined STL/CHA fixture operations use
  the audited ART-owned allocation helpers for this build.
- Changed the remote return sentinel to the canonical, unaligned address `1`.
  The old tagged address was sign-extended by this device, so normal returns
  appeared to be faults. Exact PC matching, state restoration and stop-on-fault
  behavior are retained. See the kernel's [tagged-pointer documentation](https://www.kernel.org/doc/html/latest/arch/arm64/tagged-pointers.html).
- Carrier injection, child payload loading and uploaded library loading now use
  `android_dlopen_ext` with `ANDROID_DLEXT_USE_LIBRARY_FD`. The original zygote
  path failed with an SELinux `{ open }` denial when reopening its memfd through
  `/proc/self/fd`. Passing the existing descriptor preserves normal SELinux
  mmap/execute checks and needs no policy changes. See the
  [NDK interface](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/include/android/dlext.h).
  Injection errors now include the remote linker's `dlerror` text.
- Statically linked the carrier and standalone test executables' C++ runtime,
  removing their undeployed `libc++_shared.so` dependency. Fixed the tests'
  SDK symbol spelling and APK Java-call log collection.

## ART audit

The pulled `/apex/com.android.art/lib64/libart.so`, including its `.gnu_debugdata`,
is the authority for this profile. The symbol audit checks 52 populated sites
against 18,346 ELF symbols. Layout and calling-convention checks also used
disassembly; symbol lookup alone cannot establish compatibility.

| Object | Audited offsets / sizes |
| --- | --- |
| Runtime | threads `0x240`, linker `0x250`, JIT `0x278`, cache `0x280`, instrumentation pointer `0x328`, debuggable `0x3d4`, callbacks `0x508` |
| ClassLinker / Class | CHA `0x248`, class status `0x68` |
| JIT thread pool | started `0x78`, waiting `0x80`, threads `0x88` |
| JIT code cache | saved entries `0x328`, zombie code `0x370`, zygote map `0x3b8`, collecting `0x410`, processed zombies `0x428` |
| StackVisitor / GC critical section | `0x208` / 24 bytes |
| ArtMethod | 32 bytes; flags `4`, data `16`, quick entry `24` |

The nine installed entry guards cover selectors, entry writers, native binding
and unregistration. `InitializeMethodsCode` and the outer `UpdateMethodsCode`
wrapper have no standalone symbol in this build; their inlined paths were
checked against the guarded writers. The zombie-code retirement protocol was
checked against `RemoveMethodLocked`, saved-entry publication and collection.
Runtime regressions exercise private JIT/OSR retirement, CHA dependencies, code
GC, active-frame rejection, class initialization and entry writers.

## Results

| Verification | Result |
| --- | --- |
| Rust host tests | 55 passed, including tagged-PC return regression |
| Host C++ / Java SDK boundary tests | All passed |
| Carrier/payload lifecycle | 20 load/enumerate/unload cycles; READY/PING/CALL/MODS/SHUTDOWN and worker exit passed |
| Isolated ptrace smoke | Normal calls, fd loading with a nonexistent filename, context restore and timeout/SIGSTOP passed; owned child reaped |
| ART / Java matrix | 26 script configurations passed |
| Constructors, synchronized methods, native binding, callback update | JIT, no-JIT, debuggable and real-APK AOT all passed |
| Admission / callOriginal | JIT, no-JIT and debuggable passed; AOT demo passed both verify and speed compilation |
| Java calls / JNI | app_process, real APK/WebView, no-main, static JNI and logical-disable passed |
| Native inline hooks | Native and ART processes passed: 19 hooks, concurrent callers, original calls, removal, library upload/unload, JSON/batch/overview |
| eBPF | Three checks; 50,000 call pairs, 200,000 events, five ring wraps, zero duplicate/dropped events |
| Production zygote flow | Inject/reinject, two cold launches without self-loading, lazy JNI setup, uploaded library load/unload, hook/callOriginal/delete, targets none/restore and clear passed |

The production test targets only `org.ij2art.aottest`. Zygote and system_server
PIDs stayed unchanged; the test left zygote uninjected and stopped its fixture.
The USAP pool was empty, so existing-USAP repair was not exercised. This device
uses 4 KiB pages; this run does not validate 16 KiB hardware. Android 14/16 device
regressions were not rerun. ART support remains `ENTRY_ONLY`, with logical hook
deletion; already-inlined callers are outside that contract.

Local evidence is under `out/android17/`: `matrix-results.json`, per-case logs,
`injection.log`, `lifecycle.log`, `inline-*.log`, `monitor.log`, `profile-audit.log`
and the disassembly audit files. Build outputs and evidence are intentionally
ignored by Git.

## Reproduce

Set `ANDROID_SERIAL` to the test device and ensure `adb shell su -c id` reports
root. Use a dedicated test device: APK suites replace `org.ij2art.aottest`.
Build instructions and all test scripts are listed in [test/README.md](../test/README.md).

```sh
zsh test/build-art-api.sh
zsh test/build-android.sh
zsh test/build-inline.sh
zsh test/build-java-calls.sh
zsh test/build-jni-abi.sh
zsh test/build-logical-disable.sh
zsh test/build-monitor.sh
zsh test/build-apk.sh --aot
```

Sign `out/aot-apktest-aligned.apk` with a local test key as
`out/aot-apktest-aligned-signed.apk`. Keep the same signing key across reruns.
Then run the ART feature matrix:

```sh
python3 test/run-art-api.py --serial "$ANDROID_SERIAL"
for mode in jit no-jit debuggable; do
  python3 test/run-hook-replace.py --serial "$ANDROID_SERIAL" --mode "$mode"
done
for mode in jit no-jit debuggable aot; do
  for feature in constructors synchronized native-binding hook-update; do
    python3 "test/run-$feature.py" --serial "$ANDROID_SERIAL" --mode "$mode"
  done
done
python3 test/run-aot-demo.py --serial "$ANDROID_SERIAL"
python3 test/run-java-calls.py --serial "$ANDROID_SERIAL"
python3 test/run-java-calls.py --serial "$ANDROID_SERIAL" --apk
python3 test/run-java-calls.py --serial "$ANDROID_SERIAL" --no-main
python3 test/run-static-jni.py --serial "$ANDROID_SERIAL"
python3 test/run-static-jni.py --serial "$ANDROID_SERIAL" --logical-disable
python3 test/run-inline.py --serial "$ANDROID_SERIAL" --mode native
python3 test/run-inline.py --serial "$ANDROID_SERIAL" --mode art
python3 test/run-monitor.py --serial "$ANDROID_SERIAL"
# Requires an initially uninjected zygote; do not run beside other APK suites.
python3 test/run-injection.py --serial "$ANDROID_SERIAL"
```

The isolated lifecycle/remote smoke commands are described in the main README.
Audit the exact device ELF before reusing a profile after an OTA or ART update:

```sh
adb pull /apex/com.android.art/lib64/libart.so out/libart-device.so
python3 tools/art-profile.py out/libart-device.so \
  --manifest payload/art_profiles/symbols17.inc \
  --build-id 4259bc018250195dc006f2b6cf330eb1
```

A different build ID requires a new layout/ABI/guard audit and device tests;
changing just the build-ID string or symbol offsets is insufficient.
