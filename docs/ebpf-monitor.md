# eBPF passive observation design v2: syscalls / Binder IPC / Native→Java JNI

Design draft (v2, post-review revision). It introduces a `monitor` subcommand to the CLI:
observe target app behavior passively on the kernel side with eBPF, decoupled from and
complementary to the existing payload injection paths (ART hook / inline hook).

*Chinese version: [ebpf-monitor_zh.md](ebpf-monitor_zh.md)*

**v2 changes** (relative to v1, from review):

1. The JNI uprobe probe became an **explicitly enabled optional feature**, honestly disclosing
   that it writes breakpoint bytes into the target's code pages; the "zero intrusion / fixed
   overhead" promise was withdrawn.
2. Syscall observation switched to **raw tracepoints** (`bpf_raw_tracepoint_open`); the perf
   tracepoint `trace_event_raw_sys_enter` has no `regs` field. PC attribution is downgraded to
   a best-effort frame-pointer chain.
3. Process discovery was rewritten: under the zygote model, `:remote`/USAP/isolated processes
   are not "children of the main app process", so fork tracking is only a supplement; a thread
   exit must not delete the whole process (tgid/tid discipline).
4. Binder parsing was corrected: the BC command word is **4 bytes** with no 8-byte aligned
   header; the Android 12 parcel prefix contains StrictMode/WorkSource/SYST-VNDR fields, the
   token is not in the first 4 bytes, and decoding follows the protocol table for the pinned
   version.
5. Binder two-layer events dropped "tid + nearest timestamp" merging in favor of a
   **positionally aligned queue**; entries that cannot be associated are emitted as
   unassociated status rather than guessed.
6. The syscall policy table was upgraded to **per-call argument descriptors** (argument index /
   length source / decoder type), and the aarch64 numbers were corrected: sendto=206,
   sendmsg=211.
7. The in-house loader defines an explicit **ELF subset contract** (map definition format,
   `R_BPF_64_64` only, unknown relocations rejected) instead of being described as "scanning
   for pseudo-fd patterns".
8. JNI symbols are maintained as a candidate table per API level (Android 12 uses the
   `JNI<true/false>` template instances); vaddr→**file offset** is converted through PT_LOAD,
   and uprobes are attached per process for the tracked pid.
9. The event header was corrected to 48 bytes and given a status bitfield; large events are
   assembled through a ringbuf reserve so they do not exceed the stack limit.
10. Drop accounting moved to **per-kind counter maps** on the kernel side (incremented on
    ringbuf `-EBUSY`), read directly by the CLI.
11. The fd table is maintained per tgid (shared by threads) and covers dup/dup3/close/
    close_range plus inheritance.
12. The kernel floor is unified at **5.10** (resolving the v1 D2/D3 contradiction), and the
    event channel therefore uses ringbuf.
13. Phasing was tightened: P0 does only `--pid` + syscalls, proving data accuracy first.

## 1. Goals and non-goals

Goals:

- **Syscall profiling**: record openat / execve / connect / sendto / mmap / mincore / ptrace,
  and so on, for target pids, with argument decoding and best-effort call-site attribution.
- **Binder IPC observation**: record the transaction peer, code, flags, and interface token,
  associate positionally, and mark explicitly when the association is uncertain.
- **Native→Java JNI observation (optional, off by default)**: attach uprobes to libart's JNI
  table functions and decode `RegisterNatives` to recover dynamically registered native
  methods. **This probe writes a software breakpoint instruction into the target process's
  code pages**, which is visible to in-process memory integrity self-checks; see §7.

Non-goals:

- Events are not transported over the payload control ring (the control ring has
  single-in-flight command/response semantics, and the payload only exists in processes
  injected after the fact, whereas observation must cover the pre-injection window and
  non-target processes).
- No promise of zero intrusion on the target process: the syscall/binder features are passive
  and leave no trace; the JNI feature modifies code pages.
- No Java method-level semantics, no network payload capture, and no class-rewriting
  operations.

## 2. Overall architecture and data flow

```text
               ┌─ kernel ───────────────────────────────────────────────────┐
   raw_tp      │ raw_syscalls sys_enter / sys_exit   (ctx: regs, id)        │
   perf_tp     │ binder/binder_transaction  (offsets from format)           │
   perf_tp     │ sched/sched_process_fork / sched_process_exit              │
   kprobe      │ binder_ioctl(entry)                                        │
  uprobe (opt) │ libart.so JNI symbols at file offsets, attached            │
               │ per tracked pid via perf                                   │
               │      │  BPF programs (cfg map offsets + tracked/uid)       │
               │      └─> BPF ringbuf ─(full: per-kind drop)──────          │
               └───────────┬────────────────────────────────────────────────┘
                           │ ringbuf mmap (consumer pos page + epoll)

   ij2art monitor (Rust CLI, root)
      ├─ loader: parse ELF subset → build maps → rewrite R_BPF_64_64 relocs
      │          → BPF_PROG_LOAD → attach raw_tp /
      │            perf_event_open(tracepoint|kprobe|uprobe)
      ├─ discovery: packages.list→uid, /proc polling, setresuid capture
      │             during specialization, fork supplement
      ├─ enrichment: pid→process name, pc→(lib,off) frame chain best-effort,
      │              fd table (tgid), sockaddr/parcel-token/RegisterNatives
      └─ output: text or --json JSONL; on exit print per-kind event and drop counts
```

Filtering happens in the kernel (a tracked-pid HASH plus a watched-uid HASH) and enrichment in
user space; a full ringbuf or a failed read is never silent — it is always counted and
queryable.

## 3. Design decisions

**D1 The observation path is decoupled from the payload.** The eBPF side does not inject and
does not use the control ring, so it works standalone; it covers the pre-injection window and
every process of the app; the syscall/binder features do not modify a single byte of the target
process.

**D2 The kernel floor is unified at 5.10, and the event channel uses ringbuf.** v1's
perf_event_array existed for 5.4 compatibility, but the no-BTF approach depends on
`bpf_probe_read_user/kernel` (5.5+) and bounded loops (5.3+), and even the bounded form needs
5.10, so the two claims contradicted each other. After unifying, ringbuf (5.8+) is used: a
single buffer with no per-CPU rings, and when a ringbuf reservation fails the kernel can
accumulate drop counts precisely per event kind (the perf channel's PERF_RECORD_LOST cannot be
attributed to a kind, so v1's lost[kind] promise did not hold).

**D3 No BTF and no CO-RE; offsets are obtained per attach point.**

| Attach point | ctx form | Offset source |
|---|---|---|
| raw_tp sys_enter/exit | `(pt_regs *regs, long id)` array | fixed arm64 user pt_regs layout (x0..x5@0..40, fp@232, pc@256), stored in the cfg map |
| perf_tp binder/sched | trace_event_raw_* | parse the tracefs `format` at runtime; a missing field rejects that feature (fail-closed) |
| kprobe binder_ioctl | kernel pt_regs | x2@16 is fixed; binder struct offsets are computed at host compile time from the vendor uapi headers plus static assertions |
| uprobe JNI | user pt_regs | argument registers at fixed offsets; symbol→file offset in §7 |

**D4 The in-house loader's ELF subset contract.** The supported range is explicitly narrowed,
and anything outside it is refused at load time:

- Sections: `.text` (all programs), `maps` (the map definition section),
  `.symtab`/`.strtab`/`.rel.text`; any `.rodata`, global data, or BTF section dependency is
  rejected (source discipline: constants only go through the cfg map).
- Map definitions: the repository's own `struct bpf_map_def { type, key_size, value_size,
  max_entries, flags }` (defined in `bpf/common.h`; the loader splits the `maps` section by
  symbol).
- Relocations: **only `R_BPF_64_64` in `.rel.text` that targets a `maps` symbol is accepted**;
  the loader sets the target `ld_imm64`'s src_reg to `BPF_PSEUDO_MAP_FD` and its imm to the real
  fd. Every other relocation type (R_BPF_64_ABS64/32, cross-section calls, ksym/kfunc) is
  fail-closed.
- No inter-program calls (calls within the single `.text` are resolved at link time); the
  program type and attach parameters are specified by a table on the CLI side, and the `.o`
  carries no metadata.
- The license is fixed to "GPL" (the probe_read family of helpers is gpl-only).

If contract implementation work on verifier/loader compatibility becomes too expensive,
degrade to vendoring AOSP's external/libbpf.

**D5 Kernel-side filtering plus per-kind counters.** Two HASH maps — tracked (pid→feature bits)
and watched uid — are maintained by the CLI; each feature program holds one ARRAY counter map
(emitted/dropped), which the CLI reads periodically and on exit, printing
`emitted[kind]/dropped[kind]` with no silent loss.

**D6 The event header is 48 bytes and carries status bits; large events are assembled through
a ringbuf reserve.**

```c
struct ev_hdr {          // 48 B
    u32 magic; u16 kind; u16 len;
    u32 cpu, pid, tid;
    u32 status;          // bit0 TRUNCATED, bit1 READ_FAIL, bit2 UNASSOC, bit3 UNDECODED
    u64 ts_ns;           // bpf_ktime_get_ns
    u64 pc;              // syscall feature: user-space call site; jni: uprobe target address
    u64 aux;             // nr / binder code / sym_id …
};
```

Events first call `bpf_ringbuf_reserve` (sized to the maximum length for that event kind, with
a uniform 256 B cap), then fill fields and strings directly into the reserved area and commit;
large structures are never assembled on the BPF stack. A failed string read sets READ_FAIL and
keeps the fields already obtained, and truncation sets TRUNCATED — **never guess, never drop
the whole record**.

**D7 Process discovery and lifecycle (zygote model).** See §4.1.

**D8 The honesty principle for attribution and association.** Whenever any association (binder
peer, pc's owning library, fd path) is uncertain, emit an explicit unknown status; heuristics
such as nearest-neighbor filling are forbidden.

## 4. Shared infrastructure

### 4.1 Target discovery and lifecycle

The Android process reality: app processes are forked by **zygote**, and `:remote` is a direct
child of zygote (not a child of the main app process); USAPs are pool members pre-forked
**before specialization**, and specialization produces no new fork; isolated processes use a
separate uid (99000+) and the process name `<pkg>:sandboxed_processN`. Discovery is therefore a
**combination of mechanisms**, with fork being only one link:

1. **Initial/periodic scan** (authoritative source): `--pkg` → uid from
   `/data/system/packages.list` → periodically scan `/proc/<pid>/status` (uid) +
   `/proc/<pid>/cmdline`. Isolated processes match by the cmdline prefix `<pkg>:` (covering
   `:remote`, `:sandboxed_process*`, and the WebView renderer). The period is 500 ms, which
   also backstops any omissions of the other mechanisms.
2. **Immediate capture during specialization** (shortening the blind window): a few syscall
   numbers such as `setresuid/setreuid/setuid/setresgid` **skip the tracked pre-filter** and
   check globally whether the argument uid falls in the watched-uid HASH; on a hit, the kernel
   adds that pid to tracked and emits an event. zygote/USAP specialization always passes
   through here, so tracking starts at the moment of specialization without waiting for
   polling.
3. **fork supplement**: `sched_process_fork` handles only real children whose "parent tgid is
   in tracked" (for example `Runtime.exec` forked by the app itself); zygote's forks are not in
   this category and are left to mechanisms 1/2.
4. **Exit and thread discipline**: `sched_process_exit` fires for **every exiting task**, and
   the ctx carries only a tid. The handler obtains the tgid via `bpf_get_current_pid_tgid()`:
   `tid != tgid` is a thread exit and **does not touch tracked** (it only emits a NOTE);
   only `tid == tgid` deletes the entry and emits PROC_EXIT. exec does not remove tracking; it
   only refreshes the process name.

### 4.2 Event channel

- ringbuf (8 MiB by default); the CLI statically links the stock ringbuf module from the
  pinned **libbpf v1.7.0**; `ring_buffer__new/consume_n/free` handles capacity querying, mmap,
  wraparound, and memory ordering. Waiting happens on the epoll fd that libbpf provides, and at
  most 4096 records are consumed per pass, so that `--secs`/SIGINT are still checked and output
  is still flushed during a sustained flood. Capacity comes from the map info rather than a CLI
  constant; the integration boundary is described in
  [libbpf vendoring](../third_party/libbpf/README.md).
- Output uniformly goes through `bpf_ringbuf_reserve` → fill → commit (see D6).
- A decode error (magic, kind, actual length vs. header length, data_len) is reported
  explicitly and immediately, with a non-zero exit. A normal exit detaches the probes first,
  then drains the remaining buffer and summarizes `received` together with the kernel's
  emitted/dropped counts.

### 4.3 cfg map

An ARRAY map whose slots are synchronized on both sides, in `bpf/common.h` and
`cli/src/monitor/mod.rs` (same discipline as `common/proto.h`, no negotiation). Contents: arm64
user pt_regs offsets, binder/sched field offsets parsed from the tracefs format, binder struct
offsets computed at compile time from the vendor uapi, and global switches.

### 4.4 CLI-side enrichment

- **pc attribution (best-effort, honestly labeled)**: the syscall's user PC almost always lands
  in libc's `svc` wrapper rather than the business library that initiated the call. The
  attribution flow: locate pc through maps (libc+off); then walk the frame-pointer chain from
  the saved fp (x29) (at most 8 frames, validating monotonic increase and address validity,
  with `bpf_probe_read_user` per frame), and take the first frame outside libc/vDSO as the
  initiating library. arm64 system libraries generally retain frame pointers, while third-party
  `.so` files depend on their compile options; if parsing fails, print
  `libc+0xoff (caller unknown)` rather than guessing.
- **fd table**: maintained per **tgid** (threads share the fd table). openat/openat2 on exit
  (ret≥0), dup(23)/dup3(24) (ret), close(57), and close_range(438) maintain `fd→path`; a fork
  makes the child inherit a copy; fd reuse simply overwrites; it is best-effort, and a
  failed lookup is marked unknown.
- **Decoding**: nr→name; sockaddr is decoded at a fixed size per family (IPv4 16 B, IPv6 28 B,
  with the length capped at `min(addrlen, 128)`); parcel tokens and RegisterNatives are covered
  in §6/§7.

## 5. Feature one: syscall observation

**Attach points**: raw tracepoints `sys_enter` / `sys_exit` (`bpf_raw_tracepoint_open`, program
type RAW_TRACEPOINT; the perf version of tracepoints has no `regs` in its ctx and is not used).
The ctx is an argument array: `args[0]=pt_regs*, args[1]=id(ret)`.

**The policy table is upgraded to per-call descriptors** (an ARRAY map, overridable by CLI
arguments):

```c
struct sys_policy {
    u8  action;        // DROP / HEAD (arguments only) / DECODE
    u8  arg_idx;       // index of the argument to decode
    u8  len_src;       // 0=fixed length / n=args[n] is the length / 0xff=NUL-terminated string
    u8  decoder;       // PATH / SOCKADDR / NONE
    u16 fixed_len;     // byte count when the length is fixed
};
```

Default table (aarch64 numbers, corrected):

| nr | call | decoding |
|----|------|------|
| 56/437 | openat / openat2 | PATH @ **args[1]** (execve uses args[0], so they are not shared) |
| 221/281 | execve / execveat | PATH @ args[0] / args[1] (AT_EMPTY_PATH skipped) |
| 203 | connect | SOCKADDR @ args[1], length args[2], ≤128 B (room for IPv6/unix) |
| 206/211 | sendto / **sendmsg** | sendto: SOCKADDR @ **args[4]**, length args[5]; sendmsg must follow msghdr (args[1]→msg_name), optional in P1 |
| 232 | mincore | HEAD (args[0..1] is the scan window — anti-scan intelligence) |
| 117 | ptrace | HEAD (args[0] carries request codes such as PEEKDATA) |
| 222/226 | mmap / mprotect | HEAD (PROT_EXEC and RWX determination happen on the CLI side) |
| 279 | memfd_create | PATH @ args[0] |
| 270/271 | process_vm_readv/writev | HEAD (remote iovec = args[3]; decode the scanned range in P1) |
| 147/145/146/149/143/159 | uid/gid family | global channel (discovery mechanism 2, §4.1) |
| 57/23/24/438 | close/dup family | HEAD (fd table maintenance, §4.4) |

Everything else is DROPped; `--sys all` enables everything and you own the traffic. `sys_exit`
only emits for DECODE/HEAD kinds of nr and carries ret (fd/error code).

**Rendering example**:

```text
[sys] 14:02:11.302 pid=12345 openat("/proc/self/status") ret=12 pc=libc.so+0x9a1c caller=<fp chain unknown>
[sys] 14:02:11.477 pid=12345 connect(AF_INET6 [2001:db8::1]:443) pc=libc.so+0x9c40 caller=libcronet.so+0x9f3d
[sys] 14:02:12.008 pid=12345 mprotect(0x7b2e000000,0x4000,PROT_READ|WRITE|EXEC) pc=libun8.so+0x11d4
```

## 6. Feature two: Binder IPC observation

### 6.1 tracepoint `binder/binder_transaction`

Fires in the sending task's context. The format's fields are parsed at runtime:
`debug_id, target_node, to_proc, to_thread, reply, flags, code`, all of which go into the event;
**debug_id is kept in the event** for offline reconciliation on the host. to_proc is resolved to
a process name by the CLI. This layer only consumes fields the tracepoint already exposes and
does not depend on the `binder_transaction()` function signature.

### 6.2 kprobe `binder_ioctl` (parcel header capture)

`binder_ioctl(file, cmd, arg)`: x1=cmd, x2=the user `binder_write_read*`. The corrected
write_buffer layout handling:

- **The command word is 4 bytes**, followed immediately by the command-specific payload, with
  no 8-byte aligned header (a v1 error).
- Parsing starts at `write_buffer` and is bounded by `write_size`, advancing by the **BC command
  length table** (the BC_TRANSACTION/BC_REPLY payload is `sizeof(binder_transaction_data)`,
  asserted statically by the vendor uapi plus build.rs; other BC_* commands are skipped using
  the length table). Expansion is bounded to ≤8 commands, and anything deeper is counted into a
  NOTE (batches are rare; the loss is documented).
- On a BC_TRANSACTION / BC_REPLY hit: read `code/flags/data_size/data.ptr.buffer` from
  `binder_transaction_data`, then read the first `min(data_size, 96)` bytes of the parcel. Three
  fixed-length `bpf_probe_read_user` calls, no loop. BC_REPLY marks the response direction.

### 6.3 Parcel prefix decoding (protocol table, pinned version)

The parcel prefix of Java Binder transactions varies by Android version; **for Android 12 (this
project's target), the request parcel has StrictMode policy, WorkSource uid, and SYST/VNDR
version header fields before the interface token** (v1's "the first 4 bytes are the length" was
wrong). Handling rules:

- The decode table is pinned per Android version (for A12: the above prefix → UTF-16 length →
  UTF-16LE token); it is table-driven, and new versions add entries;
- BC_REPLY parcels have a different layout (no interface token) and use a separate entry;
- If the prefix does not match (native binder without a token, or a future layout change), set
  status to **UNDECODED** and print the first 32 bytes as hex verbatim, with no guessed token.

### 6.4 Associating the two layers of events (positional, no peer guessing)

One ioctl can carry several transactions: the kprobe captures the whole batch at entry, and the
driver then processes each one as the tracepoint fires for each. `debug_id` is assigned by the
driver and **cannot be written into the kprobe-side event**, so:

- The CLI maintains two FIFOs per tid: the kprobe-side "in-batch transaction sequence" (in
  write_buffer order) and the tracepoint-side "transaction event sequence" (driver processing
  order, which is the same order);
- They are merged positionally; when the two side counts disagree (lost events, a mid-way driver
  failure, or a timeout before both sides arrive), it consumes up to the last alignable position
  and marks the remaining entries **UNASSOC** ("peer not associated");
- Queue entries unpaired for 30 s are written out as UNASSOC directly and are never matched
  against later batches.

```text
[binder] 14:02:13.88 pid=12345 -> system_server(1879) code=54 oneway=n dbg_id=8123
         token="android.app.IActivityManager"
[binder] 14:02:13.91 pid=12345 -> <peer not associated> code=55 oneway=y token=<UNDECODED>
```

## 7. Feature three: Native→Java JNI observation (optional, off by default)

**Intrusiveness disclosure (v2 correction)**: a uprobe uses `uprobe_write_opcode` to **replace
the first instruction** at the target address with a software breakpoint (BRK on arm64), meaning
bytes in the target process's code pages are modified, and an in-process memory integrity
self-check (CRC or signature scanning, including an ordinary load that reads its own code) **can
detect it**. This differs from the traceless passivity of the syscall/binder features; therefore
this feature must be explicitly enabled with `--features jni`.

**Attach method**: `perf_event_open(PERF_TYPE_PROBE, uprobe, pid=<target>)` **per tracked pid**,
rather than a global pid=-1 attach — untracked processes get zero breakpoints and zero overhead
(v1's global attach plus BPF filtering spreads the overhead across all processes, including
every hit in Call* hot paths). When the tracked set changes, attach/detach incrementally.

**Symbols and offsets (v2 correction)**:

- Android 12's JNI implementation is the `art::(anonymous)::JNI<true/false>` template instance
  (the two states of kEnableIndexIds), and the internal C++ mangled names **do not constitute a
  stable ABI**. The candidate symbol table is maintained per API level, and at load time each
  candidate is resolved and verified against the actual libart file (reusing the resolution chain
  that prefers on-disk section headers and falls back to remote PT_DYNAMIC, but with a separately
  maintained candidate table that is not mixed with ADAPTER_SYMBOLS); anything that cannot be
  resolved is skipped and reported in the startup summary.
- A uprobe needs a **file offset**, not a vaddr: sym_vaddr returns an ELF virtual address and
  MemElf returns a runtime address, and both must be converted through PT_LOAD
  (vaddr↔offset) before attaching.
- The attachability of `RegisterNatives` on a real device's libart (whether the leading
  instruction suits uprobe replacement) is the **entry gate for P2**; if it fails, this feature
  degrades to low-frequency symbols only, or is dropped.

**Default symbol set** (low frequency): FindClass, GetObjectClass, GetMethodID,
GetStaticMethodID, GetFieldID, GetStaticFieldID, RegisterNatives, DefineClass, NewStringUTF.
The `Call<type>*` family is off by default; even with `--jni-calls`, they are only aggregated as
(pid, sym) counts rather than per-hit events (breakpoint overhead occurs on every hit, and
aggregation only saves traffic, not overhead — the documentation states this honestly).

**RegisterNatives decoding** (the core output): `JNINativeMethod{name*, sig*, fnPtr}` is read
with a bounded read of the first 8 entries, using two `bpf_probe_read_user_str` calls plus
fnPtr; fnPtr is attributed from a runtime address to lib+off (reusing the maps cache from §4.4),
and a hit in an anonymous executable mapping is labeled "suspected dynamically generated code".

## 8. Loader and build

```text
bpf/                 # common.h (event header/map definitions/cfg slots), sys.c, binder.c, jni.c, track.c
third_party/binder-uapi/   # a few headers such as binder.h; build.rs computes offsets + static assertions at compile time
cli/src/monitor/
  ├ mod.rs / loader.rs / attach.rs / events.rs / enrich.rs / offsets.rs
out/monitor.bpf.o    # NDK clang -target bpfel-unknown-none -O2 -mcpu=v2; embedded with include_bytes!
```

- The loader implements the D4 contract; raw_tp uses `bpf_raw_tracepoint_open`, and
  perf_tp/kprobe/uprobe use `perf_event_open` (tracepoints must first read tracefs to obtain the
  event id).
- build.rs generates offsets.rs (binder struct/command constants plus static assertions), which
  is synchronized on both sides together with the cfg slot table.

## 9. `monitor --check`

The current P0 is an **arm64 syscall end-to-end self-check**: root, kernel ≥5.10, load the real
sys_enter/sys_exit programs, map the actual event map through libbpf, and then attach the raw
tracepoints. Only its own TGID is added to tracked, and only the openat policy is enabled;
reading `/dev/null` does not modify any file.

By default it uses a 64 KiB (at least one page) ringbuf and produces 1024 enter/exit pairs in a
row. Each openat uses a distinct mode marker (without O_CREAT, that argument does not affect the
file), and PID/TID, nr, path, arguments, return value, timestamp, and the executable mapping
owning the user PC are all verified; the accumulated data crosses the buffer more than 7 times.
Failing to receive complete event pairs within 5 seconds is a failure; so are extra, duplicate,
or corrupt events, and kernel counter mismatches. This simultaneously validates map capacity
querying, wraparound, and user-space decoding. Every exit path releases the probes and maps.

Later P1/P2 binder/sched/kprobe/uprobe capabilities should each add their own end-to-end
self-check; a passing `--check` today only means the implemented syscall channel passes and does
not prove Binder/JNI capability.

Reproduction: `zsh test/build-monitor.sh`, then
`python3 test/run-monitor.py --serial <device serial>`. That script repeats the self-check 3
times and starts an independent fixture that performs 50,000 openat/close pairs, verifying the
order, unique markers, and counts of all 200,000 JSON events on the real 8 MiB ringbuf. Logs are
saved under `out/monitor-validation-*`. Device-side Rust tests can additionally use
`monitor:: --include-ignored --test-threads=1` to verify failure paths: deliberately corrupting
the magic must fail immediately, and changing submit to discard must fail with a timeout.

**Tracefs transient-mount discipline** (part of leaving no trace): raw_tp does not depend on
tracefs; kprobe attaches directly through `PERF_TYPE_PROBE` on 5.10 and needs no persistent
kprobe_events; only perf tracepoints need tracefs to obtain the event id/format — and mounting it
on a device where it is unmounted by default would show up in `/proc/mounts`. The flow is
therefore fixed as "mount → read id/format → perf_event_open → unmount": the perf event's
lifetime does not depend on the mount point, so no enumerable mounts difference is left for the
target.

## 10. Risks and degradation

| Risk | Mitigation |
|------|------------|
| Vendor kernels drift in binder/sched tracepoint fields | Offsets are parsed from the format at runtime; a missing field rejects that feature and does not affect sys (raw_tp does not depend on the format) |
| binder struct / parcel prefix changes across versions | uapi + build.rs static assertions; parcels follow a per-version protocol table, and unknown layouts become UNDECODED instead of guesses |
| Positional association misaligns when events are lost | Pair only when both side counts agree; otherwise consume to the alignment point and mark the remainder UNASSOC; write out on timeout |
| A missing frame-pointer chain breaks caller attribution | best-effort plus an explicit "caller unknown" label; never guess |
| uprobe breakpoints detected by self-checks / hot-path overhead | Feature off by default, attached per pid, Call* aggregated only, with the overhead semantics disclosed |
| Loader input outside the contract | Unknown sections/relocation types are fail-closed; the fallback is vendoring AOSP libbpf |
| ringbuf flooding | Kernel-side default drops of noisy nr; per-kind emitted/dropped counters are always available |
| /proc/mounts exposing the tracefs mount | Transient mount (unmount after reading id/format); kprobe goes through PERF_TYPE_PROBE; raw_tp has no dependency |
| Timing side channel: global attach-point overhead can in theory be measured statistically | Analysis-window-scoped attach; default policy drops high-frequency nr; overhead is in the hundreds of ns to µs range, a different order of magnitude from ptrace stops |
| The monitor process / root environment being discovered by process-enumeration detectors | The same class of environmental trace as a Frida server, not introduced by the observation mechanism; eliminating it is out of scope for this project |
| Missed capture during specialization (a vendor changed the specialization path) | Periodic /proc scanning as the backstop (authoritative source), bounding the blind window to ≤500 ms |

## 11. Test plan

Device-side `test/run-monitor.py` (extending the fixture app) plus host-side `cargo test`:

2026-09-16 libbpf consumer regression record: OnePlus PLC110 / Android 16 /
`6.6.118-android15-8-ge58033dc8ea6-abogki498046332-4k`, page size 4096. The 38 host tests and 12
device monitor tests passed (including real BPF object parsing and two fault injections).
`--check` passed 3 times in a row, each with 2048 events and more than 7 rounds of 64 KiB ringbuf
wraparound. The real 8 MiB ringbuf received 200,000 events with 5 wraparounds, and the unique
markers, order, and kernel counts all agreed, with no duplicates and no drops. In an additional
unthrottled flood, `--secs 1` returned in about 1.2 seconds with
received=230433=emitted_enter+emitted_exit, and the overflow was reported through the dropped
counter.

- **Data accuracy (the core P0 acceptance criterion)**: openat/execve/connect (IPv4+IPv6)/sendto
  argument decoding matches expectations; ret/fd association is correct; the
  mincore/process_vm_readv anti-scan intelligence fields are correct.
- **Cold start / USAP**: on both the `am start` and USAP specialization paths, the gap between the
  first event and the specialization setresuid is ≤ one polling period; `:remote` and isolated
  processes are discovered and tracked.
- **Thread exit**: the fixture starts and stops 100 threads; tracked entries are not deleted by
  mistake and there are no spurious PROC_EXIT reports.
- **Batched Binder**: with a fixture issuing multiple transactions in one ioctl, positional
  association is correct for each entry; deliberately losing events on one side marks the
  corresponding entries UNASSOC rather than mispairing them.
- **Token decoding golden test**: compare real A12 transactions (for example triggered by
  `service call`) against known interface names.
- **Deliberate packet loss**: 1 MiB ringbuf under load; dropped[kind] agrees with the replay
  count and there is no silent loss.
- **RegisterNatives**: trial attach on a real device's libart plus a fixture doing dynamic
  registration; the (name/signature/lib+off) triple is correct.
- Stability: 10 minutes with bounded RSS, bounded maps cache, and zero drop counts (default
  policy).

## 12. Phasing (reviewed version)

- **P0**: loader + cfg/tracked + ringbuf + `--check` + **syscall feature with `--pid` only**.
  Acceptance = every data-accuracy item in §11; `--pkg` is not enabled before that.
  Implementation status: landed and verified on real devices (OnePlus 13 / Android 16 / kernel
  6.6.118 GKI, 2026-09): `--check` fully passes; the ringbuf data-area base address (+1 page),
  arm64 pt_regs offsets, frame-chain caller attribution, fd table association (openat/dup3), the
  three sockaddr families (IPv4/IPv6/AF_UNIX), multithread coverage, and drop counting were all
  verified correct. Original consumer flood baseline: 1.97 million events in 5 s with zero loss
  under the default policy; `--sys all` reaches about 1M events/s for a single process, and ring
  overflow is reported honestly through the dropped counter.
  Fix record: the sys_exit tid→nr entry is now deleted on consumption (otherwise the exit of a
  call that was never allowed through would emit an event under a false identity).
  The consumer now uses libbpf v1.7.0; this round's acceptance data and self-check coverage are
  in §9 and §11.
- **P1a**: process discovery (uid/cmdline/specialization capture/lifecycle) + `--pkg`.
- **P1b**: binder routing (tracepoint + debug_id + to_proc enrichment).
- **P1c**: binder_ioctl kprobe + parcel protocol table + positional association.
- **P2**: optional JNI probes (off by default; attaching RegisterNatives on a real device is the
  gate).
- **P3 (candidates)**: syscall aggregate profiling mode, process_vm_readv/mincore scan-range
  decoding, `do_page_fault` page-fault probing, read watchpoint sentinels (`--watch`), BR_REPLY
  capture, and linking mprotect/memfd events to an automatic `ctl read` dump.
