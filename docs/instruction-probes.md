# Instruction observation points

`ctl probe` observes the **register state before one arm64 instruction executes**.
It uses the vendored ShadowHook instruction interceptor in the injected payload;
no replacement library, DEX or eBPF support is needed. The interceptor patches the
target instruction and resumes its original behavior after recording a snapshot.
This feature records selected observation points, not a continuous branch trace.

*Chinese: [instruction-probes_zh.md](instruction-probes_zh.md)*

## Commands

```sh
# Absolute runtime address. Use addresses from this process instance.
./ij2art ctl --pid P probe add --target 0x7123456010 --max-hits 100

# Instruction 16 bytes into a function; the module path suffix must match uniquely.
./ij2art ctl --pid P probe add --target target_function --in /libexample.so --offset 0x10

# ELF virtual address + the module's relocation/load bias, NOT a file offset or
# an offset from the beginning of its executable mapping.
./ij2art ctl --pid P probe add --in /libexample.so --offset 0x12340

# Optional filters: one Linux thread and an exact unsigned register value.
./ij2art ctl --pid P probe add --target target_function --in /libexample.so \
    --tid T --when x0=0x42 --max-hits 20

./ij2art ctl --pid P --json probe list
./ij2art ctl --pid P --json probe query 1
./ij2art ctl --pid P --json probe read 1 --after 0 --limit 48
# Use the previous response's data.next_seq to read the following batch.
./ij2art ctl --pid P --json probe read 1 --after 48

# First quiesce all callers of the instruction, including callbacks in flight.
./ij2art ctl --pid P probe del 1
```

`--target` accepts an absolute `0x` address or a symbol. A symbol requires `--in`;
an absolute address cannot be combined with `--in`. With a target, `--offset` is
added to that target; without a target, both `--in` and `--offset` are required.
Offsets and final addresses must be 4-byte aligned. A module selector also works
with the exact `module` returned by `ctl lib load`, including deleted memfd paths.

`--tid 0` (default) permits any thread. A nonzero TID must currently belong to the
target process; it identifies a numeric Linux TID, so stop the probe when that
thread exits to avoid matching a later reuse. `--when xN=VALUE` accepts x0..x30
and an unsigned decimal or hexadecimal 64-bit value. Without it, all register
values match. Filtering precedes hit counting.

`--max-hits 0` (default) is unlimited. A positive limit stops collection after that
many matching hit attempts, including attempts dropped under contention. The
instruction remains patched until `del`. Successful add returns the probe ID;
after a timeout, use `list/query` before retrying installation.

## Records and cursors

Each probe owns a separate in-process buffer for its latest 256 snapshots. The
callback never waits for the CLI or a buffer lock; a contended hit is dropped and
counted. The control ring only transports bounded snapshots of that buffer when
`read` is requested. Reads are non-destructive and return at most 48 events.

| Field | Meaning |
| --- | --- |
| `probe` | Configuration, state, original instruction word and cumulative counters |
| `events[].seq` | Per-probe publication sequence, starting at 1; use as a cursor |
| `events[].hit` | Matching hit attempt number; order may differ from publication order across threads |
| `events[].ts_ns` | `CLOCK_MONOTONIC` timestamp taken inside the callback; not instruction retirement time |
| `events[].tid` | Thread that hit the instruction |
| `events[].pc`, `sp` | Original instruction address and stack pointer |
| `events[].nzcv` | Condition flags; **not** the full architectural PSTATE |
| `events[].regs` | Raw x0..x30 values; x29 is FP and x30 is LR, including any pointer-authentication bits |
| `events[].clock_failed` | Timestamp collection failed; `ts_ns` is zero |
| `next_seq` | Exclusive cursor for the next read |
| `more` | More records existed after this batch at snapshot time |
| `lost` | Records after the requested cursor that have already been overwritten |

`hits` counts admitted matching attempts; `captured` counts published snapshots;
`dropped` counts attempts lost to contention; `overwritten` counts snapshots
evicted from the rolling buffer. After callers have quiesced,
`hits = captured + dropped`. Live counters can include callbacks still in flight.
Overwriting is distinct from dropping: an overwritten event may already have been
read. Always inspect both `lost` and `dropped` when evaluating coverage.

Start at `--after 0`, then advance to `next_seq`. Repeating a cursor is safe, but
old events may have been overwritten in the meantime. A cursor ahead of `captured`
is rejected. `-75` means a writer currently owns the buffer: retry the same cursor.
The sequence orders observations of this probe only, not all probes or all threads.
`--json`, `ctl batch` and `ctl overview` include probes through the usual envelopes.

## Lifetime and execution boundaries

- States are `ACTIVE`, `LIMITED`, `REMOVED` and `ERROR`. `LIMITED` stops capture
  while retaining the patch. Remove all installed probes before control-ring
  shutdown or unloading an uploaded target library.
- `del` is a physical unintercept, idempotent after success. As with `inline del`,
  callers must be quiescent, including threads already executing the interceptor.
  Backend installation or removal failure records `ERROR` and requires a process
  restart: failure does not prove that code was restored. Keep the ELF pinned and
  do not reuse a consumed backend handle.
- IDs and buffers are never reused: up to 64 installations per process lifetime,
  about 76 KiB of snapshot storage each. Recorded events remain readable after
  removal. File-backed ELF pins remain until process exit; an uploaded library can
  be unloaded after removing its probes and quiescing all callers.
- The target must be a valid instruction in an already loaded, readable executable
  ELF mapping outside the payload. Anonymous/JIT code and payload internals are
  unsupported. A probe and a user inline hook cannot share the same target address.
  No disassembler checks whether an aligned address is actually code: do not point
  probes at embedded data or into an exclusive-load/store sequence.
- The callback preserves general registers, NZCV and FPSIMD state and never changes
  the supplied context. Vector registers are preserved but not reported. This does
  not provide SVE/SME state guarantees or preserve exclusive-monitor state.
- Instrumentation changes timing and code bytes. Use bounded hit counts for hot
  locations. Snapshots are taken before the selected instruction; a fault or signal
  can still prevent that instruction from completing.

## Verification

```sh
zsh test/build-probe.sh
python3 test/run-probe.py --serial DEVICE
```

The build runs the host concurrent-buffer regression and builds the real payload,
CLI and native fixtures. The device suite uses a fresh isolated process and covers
GPR/NZCV values at an interior instruction, live SIMD preservation, address/symbol/
module-offset resolution, filtering, limits, concurrent producers, overwrite and
cursor semantics, physical instruction restoration and uploaded-module lifetime.
