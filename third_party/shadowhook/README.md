# Vendored ShadowHook (arm64 native address hooks)

Source: https://github.com/bytedance/android-inline-hook

Pinned release: **v2.0.1**, commit `854c775c2c3676e57a0f383597ebf420b5204161`.
`UPSTREAM.json` records original SHA-256 hashes and upstream paths relative to
`shadowhook/src/main/cpp` (`LICENSE` at this directory's root comes from the
upstream repository root). `sources.txt` is the explicit build input list.

## Copied scope

58 upstream files, approximately 692 KiB: the arm64 implementation, native public
header and its C dependency closure, xDL (including debug-symbol decompression),
BSD container headers, Linux syscall headers, and licenses. The ELF/address
helpers remain necessary even when the CLI resolves the function address:
ShadowHook uses them for instruction boundaries, branch islands and safe calls.

Java, JNI bindings, arm32, Gradle, demos, upstream tests, the standalone shared-library
build/export map, and `libshadowhook_nothing.so` are excluded. We preserve complete required
source files instead of splitting their internal functions into a new fork.
Unused functions are removed at link time. Builds require no network or external
ShadowHook installation.

## Local patch

`shadowhook.c`: guard the calls to `sh_linker_init()` and `sh_task_init()` with
`#ifndef IJ2ART_SHADOWHOOK_ADDRESS_ONLY`. This build always defines the macro.
It disables automatic linker constructor/destructor hooks, soinfo scanning and
pending hooks for future library loads, and removes the helper `.so` dependency.
The instruction engine, fault protection, original-pointer publication and
unhook implementation are unchanged.

This is an internal **address-only** integration, not the complete upstream API.
Only our wrapper invokes it, using UNIQUE mode and already loaded function
addresses. Participating ELF handles are retained for process lifetime. The
wrapper does not offer pending name hooks or automatic tracking of `dlclose`.
All upstream symbols are local to the payload (`--exclude-libs,ALL`), so they do
not interpose on another copy of ShadowHook in the App.

## Updating

Re-copy the same path set from an explicitly pinned upstream commit; review any
new dependency and API changes, apply the small address-only patch, regenerate
the hash manifest, and run the native fixture plus ART CheckJNI regression.
Do not disable signal protection or branch islands to reduce the copy size.

## Licenses

ShadowHook: MIT, see `LICENSE`. xDL: MIT, see `third_party/xdl/LICENSE`.
Linux syscall support: BSD, see `third_party/lss/LICENSE` and source headers.
BSD containers retain their license notices in `third_party/bsd/{queue,tree}.h`.
xDL's LZMA wrapper is also MIT-licensed; it uses Android's system `liblzma.so`
when compressed debug symbols are needed. Distributions of the binaries must
include these notices; the build collects them in `out/THIRD_PARTY_NOTICES.txt`.
