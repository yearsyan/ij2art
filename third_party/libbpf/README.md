# libbpf ring buffer

Pinned upstream: **v1.7.0**, commit
`f5dcbae736e5d7f83a35718e01be1a8e3010fa39` from
https://github.com/libbpf/libbpf.

`src/ringbuf.c`, public headers and `include/` are unmodified upstream files.
`SHA256SUMS` records all verbatim files. To verify locally:

```sh
(cd third_party/libbpf && shasum -a 256 -c SHA256SUMS)
```

The CLI statically compiles the upstream ring-buffer module, including its map
info lookup, mmap sizing, producer/consumer protocol, barriers and polling.
It does not require an Android system libbpf.so. The ELF loader in
`cli/src/monitor/loader.rs` remains unchanged; this is not a full libbpf build.

Two explicitly maintained integration files avoid unrelated libelf/zlib build
dependencies for this standalone module:

- `src/libbpf_internal.h`: only logging declarations, allocation, option
  validation and errno helpers, extracted verbatim from upstream's internal
  header, plus standard includes and `offsetofend`.
- `src/support.c`: `BPF_OBJ_GET_INFO_BY_FD` (using upstream's UAPI struct and
  syscall semantics) and stderr/error-string adapters. No ring logic lives here.

When updating, replace verbatim files together, refresh checksums, re-extract
the internal helpers, review support.c against upstream, then run host tests and
`test/run-monitor.py` on Android. Keep the upstream algorithm and barriers
unmodified. Linux/Android builds use cc in cli/build.rs; macOS host tests do not
compile or link this Linux-only module.

Upstream is dual licensed LGPL-2.1 OR BSD-2-Clause; this integration uses the
BSD-2-Clause option. Retain the copyright headers and license notices when
distributing. `build.sh` appends them to `out/THIRD_PARTY_NOTICES.txt`.
