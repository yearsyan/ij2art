# Dynamic ART compatibility

*Chinese: [art-compatibility_zh.md](art-compatibility_zh.md)*

ART replacement now uses version constraints, symbol capabilities and runtime probes,
following the compatibility approach used by [LSPlant](https://github.com/LSPosed/LSPlant).
The libart GNU build ID is no longer an allowlist key. It is retained for diagnostics
and matching the loaded image to its ELF file. Artifact identity checks between the
CLI, carrier and payload still apply.

## Discovery

- Read the actual loaded `libart.so`: `.dynsym`, `.symtab` and `.gnu_debugdata`.
  Resolve complete ABI signatures, with explicit alternatives and normalized LLVM
  `.__uniq.` / `.llvm.` suffixes. Multiple distinct matching addresses are an error.
  Bindings and entry bytes come from this ELF, with no compiled-in function RVAs.
- Select locked-code or zombie-code retirement from available symbols. Detect
  zombie bookkeeping independently of the extra `jit_mutator_lock_`: Android 15
  protects its zombie sets with `jit_lock_` alone. Require all entry guards and
  protocol operations before enabling replacement.
- Analyze bounded ARM64 field accesses in Runtime, JIT, thread-pool, ClassLinker,
  cache and visitor functions. No fabricated ART objects or target-method writes
  are used for probing. Identify Jit through its cache/options access relationships,
  and prefer `IsImagePointerSize` for ClassLinker; large functions need not read just
  one Runtime pointer field. Recognize GPR-to-FP moves, local pointer spills and
  canonical in-image PLT tail calls. Overlapping stores, conflicting paths and
  potentially callee-modified stack addresses invalidate spill provenance.
- Probe ArtMethod spacing and accessFlags using several real Throwable constructors;
  verify quick entries, declaring classes and ART's own field accesses. This works
  with opaque JNI method IDs too.
- Validate the live Runtime object graph, including shared Runtime/Jit cache ownership
  and tagged native-heap addresses. Check mapped entry bytes before installing guards.

Successful bindings remain immutable. The full ELF/debug image is then released.
Known SmallPatternMatcher entry families are collected by symbol name, replacing
per-build RVA arrays. See `payload/art_discovery.h`, `payload/art_profile.cpp` and
`payload/art_symbols.inc`. `payload/art_profiles/` now contains historical audit
records only and is not compiled into production.

## Scope

This keeps the project's strict admission, JIT/OSR/CHA retirement, callOriginal,
concurrent updates and entry protection. It does not establish LSPlant's entire
Android version coverage.

Current constraints are API 34–37 / arm64, two retirement families and four internal
layout rules derived from Android 14–17 audits. Every image must still
pass all symbol and layout checks. Runtime threads/JIT/linker/debug/callback offsets,
ArtMethod layout, pool fields and visitor extent are probed. Instrumentation, CHA and
some cache offsets remain explicit rules with instruction-access evidence. Private
STL layouts, flags and lock semantics remain protocol assumptions that require rule
updates when ART changes them. Symbol presence alone does not prove compatibility.

Verification targets are OnePlus PLC110 / Android 16, CIX P1_EVB / Android 14 and
an AOSP Android 15 ARM64 emulator, all with 4 KiB pages. The initial dynamic backend
was also tested on Pixel 7 / Android 17; that device has not been rerun after these
probe fixes. Other Android 15 ROMs and 16 KiB devices are unverified. The hook contract remains
`ENTRY_ONLY` with logical deletion; previously inlined callers are outside it.

Missing/ambiguous symbols, unknown instruction forms or incompatible layouts report
`replacement:false` with `unsupported_reason`; DEX and method-query capabilities
remain available. Success reports `compatibility:"symbols-probes-v1"` and the selected
backend. A mismatch between loaded and on-disk ELF identity is also rejected.

## Verification

```sh
adb pull /apex/com.android.art/lib64/libart.so out/libart-device.so
python3 test/run-art-discovery.py out/libart-device.so --api 37
```

This host regression runs the production ELF/decoder/ABI discovery code. It checks
real ELF acceptance, same-address aliases, ambiguous LTO clones, missing required
symbols, an unregistered build ID, and relocation of all symbol/pattern addresses by
16 KiB. It also rejects a removed field access, truncated ELF and invalid section
bounds, and exercises signed loads, register renaming, unknown writes and conflicting
control-flow origins in the decoder. Additional cases cover distinct GPR/FP registers,
pointer spills and paired accesses across calls, and rejection after overlapping or
unknown-address stores, frame exposure and conflicting spill origins.
Relocation is a simulated new-build regression, not another device or a
16 KiB page-size test. It never writes the source ELF or device ART.

Device suites are listed in [test/README.md](../test/README.md). The Android 14/16
recheck evidence is under `out/art-compat-recheck-20260917/`; the initial migration
used `out/art-dynamic/`. The initial Android 17 adaptation report is
[android17.md](android17.md).

## Android 15 emulator (2026-09-17)

The reusable AVD is `ij2art_api35_root`, using
`system-images;android-35;default;arm64-v8a` revision 2 and Emulator 36.6.11.
Android Studio is not required. The AOSP image supports `adb root`, as described in
the [Android Emulator documentation](https://developer.android.com/studio/run/managing-avds?hl=en).
This run used serial `emulator-5554`, API 35, 4096-byte pages and SELinux Enforcing.

- Fingerprint: `Android/sdk_phone64_arm64/emu64a:15/AE3A.240806.019/12368160:userdebug/test-keys`.
- ART build ID: `05bfa63ad29b97d7dde4e764ce193f37`.
- Backend: `arm64-zombie-code-jit-lock-dynamic`.

The previous build correctly rejected this ART because no verified private-layout
rule matched. Android 15 already maintains zombie and processed-zombie code sets,
but uses only `jit_lock_` and embeds Instrumentation directly in Runtime. Detection
now separates those properties. Retirement removes both sets before freeing code;
the additional lock is used only when present. These semantics are visible in
AOSP's [JIT cache declaration](https://android.googlesource.com/platform/art/+/refs/heads/android15-release/runtime/jit/jit_code_cache.h)
and [retirement implementation](https://android.googlesource.com/platform/art/+/refs/heads/android15-release/runtime/jit/jit_code_cache.cc).

The new rule is checked against actual ELF instructions. An inlined ZygoteMap
lookup is accepted only when both ArrayRef words match the standalone method's
accesses. Test fixtures also resolve this ART's outlined STL helpers to seed real
CHA and processed-zombie entries. Missing zombie erase operations and ambiguous
protocol symbols are negative regressions; a missing Android 15 zombie marker
must not silently select the non-zombie backend.

| Layout evidence | Offset / size |
| --- | --- |
| Runtime threads / linker / Jit / cache | `0x248 / 0x258 / 0x280 / 0x288` |
| Inline Instrumentation / callbacks / debug state | `0x328 / 0x688 / 0x554` |
| ClassLinker CHA / class status | `0x260 / 0x70` |
| Pool started / waiting / thread vector | `0x78 / 0x80 / 0x88` |
| Saved entries / zygote map / collecting | `0x328 / 0x3d0 / 0x408` |
| Zombie / processed-zombie sets | `0x370 / 0x3a0` |
| StackVisitor / GC critical section | `0x1f0 / 0x18` bytes |

| Android 15 verification | Result |
| --- | --- |
| Host discovery and rejection cases | 8 groups passed |
| ART / Java device matrix | 26/26 |
| Native / ART inline hooks | 2/2 |
| Production injection | 1/1, including two cold launches |
| Total device cases | 29/29 |
| Entry guards / permanent patterns | 8 / 412 |
| Final state | Injection cleared, fixture APK removed, zygote/system_server and boot ID unchanged |

The matrix exercises JIT/OSR retirement, CHA and processed-zombie cleanup,
callOriginal, constructors, synchronized and JNI methods, callback updates, and
real APK AOT. Production injection also checks targets none/restore and clear.
SELinux stayed Enforcing; the root emulator remains running, unlocked and awake.

The same rebuilt artifacts were rerun on OnePlus / Android 16 and LAN / Android 14:
both finished with 29/29 cases and eight host discovery groups. The LAN run first
failed in `constructors-aot` with `no ready control ring matching the current CLI
layout found`. A fresh diagnostic run and the resumed matrix both passed that case.
The cause was not determined; no retry or behavior change was added to the CLI.
The original failure log is retained alongside the successful reruns. All three
devices ended with injection cleared and the fixture removed, with unchanged
zygote/system_server PIDs, boot IDs and SELinux modes during this matrix.

Evidence and the startup command are under `out/android15-validation-20260917/`.
Its `verification.json` links build/source hashes, per-device results, failure
evidence and final state. Rust tests passed 55/55, along with two Java SDK and four
C++ boundary/concurrency groups.
For a subsequent run, start the saved AVD, wait for `sys.boot_completed=1`, run
`adb -s emulator-5554 root`, unlock it, and run the suites with that explicit serial.
The AVD was created separately from existing virtual devices.

## Android 14/16 recheck (2026-09-17)

Both devices initially rejected replacement with `ART Runtime getter/field probe
unavailable or ambiguous`. The fixes distinguish Jit from JitOptions and use a
dedicated ClassLinker probe, recognize outlined cleanup and zombie-set accesses,
and preserve pointer provenance through valid stack spills, FP moves and PLT
delegation. No build-ID allowlist or per-build function addresses were added.

| Verification | OnePlus PLC110 | LAN CIX P1_EVB |
| --- | --- | --- |
| Device / Android | `3B65A80052F00000` / 16, API 36 | `192.168.9.127:10000` / 14, API 34 |
| ART build ID | `7bf2886127ae5230f6030d2e8fa42561` | `1baa085e52462906909d6dfe1b6332e2` |
| Dynamic backend | zombie-code | locked-code |
| Host discovery and rejection cases | 8 groups passed | 8 groups passed |
| ART / Java device matrix | 26/26 | 26/26 |
| Native / ART inline hooks | 2/2 | 2/2 |
| Production injection | 1/1, actual target parent selected | 1/1 |
| Total device cases | 29/29 | 29/29 |
| Entry guards / permanent patterns | 9 / 412 | 8 / 412 |
| Page size / SELinux | 4096 / Enforcing | 4096 / Disabled (original state) |

The device matrix covers JIT, no-JIT, debuggable/opaque JNI IDs and real APK AOT,
including constructors, synchronized methods, native binding, callback updates,
callOriginal and logical deletion. Production injection checks two cold launches
with self-loading disabled, uploaded-library load/unload, targets none/restore and
clear. Existing USAP injection was exercised on OnePlus. Rust unit tests passed
55/55; both Java SDK groups and all four C++ boundary/concurrency groups passed.

OnePlus had a legacy `ebpf4art` carrier from another build. Identity validation
refused to manipulate it; an explicitly authorized reboot removed it. The device
was then unlocked and set to stay awake. Its two zygotes route the fixture through
the primary instance, whereas the CLI's stopped-target heuristic selected the
secondary instance. The regression now learns the actual parent from a warm-up
launch and pins subsequent commands to it. For manual use, start the target before
`inject --targets`, or provide the verified `--pid`; the cold-target heuristic
remains a limitation, unrelated to ART discovery.

The LAN WebView assertion was corrected for `userdebug` ROMs: Chromium intentionally
retains devtools after a disable call on debug Android builds. The suite waits for
the socket state and checks that policy, as implemented in Chromium 119's
[SharedStatics](https://chromium.googlesource.com/chromium/src/+/119.0.6045.141/android_webview/glue/java/src/com/android/webview/chromium/SharedStatics.java)
and [BuildInfo](https://chromium.googlesource.com/chromium/src/+/119.0.6045.141/base/android/java/src/org/chromium/base/BuildInfo.java).

Both devices finished uninjected, with the fixture APK removed and SELinux modes
unchanged. OnePlus zygote/system_server PIDs remained stable after the authorized
reboot; LAN PIDs and boot ID remained stable throughout. The manifest
`out/art-compat-recheck-20260917/verification.json` links artifact hashes, per-device
`matrix-results.json`, discovery results, failure evidence and final state.

## Earlier Android 17 verification (2026-09-17)

Pixel 7 / Android 17 / API 37, ART `4259bc018250195dc006f2b6cf330eb1`:

| Verification | Result |
| --- | --- |
| Host discovery and rejection cases | 6 groups passed, including unknown build ID and full address relocation |
| Java SDK / C++ boundary and concurrency tests | All passed |
| ART / Java device matrix | 26/26 across JIT, no-JIT, debuggable and real APK AOT |
| Entry guards / permanent patterns | 9 guards; 412 entries discovered dynamically |
| Production zygote flow | Two cold launches, hook/callOriginal/logical deletion, target changes and clear passed |
| Cleanup | Injection cleared; zygote/system_server PIDs unchanged; SELinux Enforcing |

Final artifacts, hashes and per-case evidence are recorded in
`out/art-dynamic/verification.json`, `matrix-results.json`, `discovery.log` and
`injection.log`.
