# Historical exact-build audit records

These manifests reproduce the initial Android 14/16/17 audits. Production no longer
includes them or selects ART by build ID. Current symbol alternatives live in
`../art_symbols.inc`; ABI discovery lives in `../art_discovery.h` and `../art_profile.cpp`.

`tools/art-profile.py` can still check these old records. Use
`test/run-art-discovery.py ELF --api API` to test the current discovery implementation.
