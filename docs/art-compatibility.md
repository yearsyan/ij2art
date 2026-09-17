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
- Select locked-code or zombie-code retirement from available symbols. Require all
  entry guards and protocol operations before enabling replacement.
- Analyze bounded ARM64 field accesses in Runtime, JIT, thread-pool, ClassLinker,
  cache and visitor functions. No fabricated ART objects or target-method writes
  are used for probing.
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

Current constraints are API 34–37 / arm64, two protocol families and three internal
layout rules derived from the earlier Android 14/16/17 audits. Every image must still
pass all symbol and layout checks. Runtime threads/JIT/linker/debug/callback offsets,
ArtMethod layout, pool fields and visitor extent are probed. Instrumentation, CHA and
some cache offsets remain explicit rules with instruction-access evidence. Private
STL layouts, flags and lock semantics remain protocol assumptions that require rule
updates when ART changes them. Symbol presence alone does not prove compatibility.

Only the Pixel 7 Android 17 device has been retested with this dynamic backend.
Earlier Android 14/16 test results do not validate the new discovery code on those
devices. Android 15, other vendors and 16 KiB devices are unverified. The hook contract
remains `ENTRY_ONLY` with logical deletion; previously inlined callers are outside it.

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
control-flow origins in the decoder. Relocation is a simulated new-build regression, not another device or a
16 KiB page-size test. It never writes the source ELF or device ART.

Device suites are listed in [test/README.md](../test/README.md). Evidence for this
migration is under `out/art-dynamic/`; the initial Android 17 adaptation report is
[android17.md](android17.md).

## Results (2026-09-17)

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
