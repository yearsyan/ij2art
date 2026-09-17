# ij2art

Android app debugging tool built on ptrace + zygote. The CLI loads a carrier into zygote;
target processes inherit it through fork and load the embedded payload during
specialization. Once the domain switch succeeds, the payload establishes a shared-memory
control channel.

The project is a prototype and only maintains the current implementation. It requires a
root environment with ptrace, process-memory, and `pidfd_getfd` permissions; the build
target is AArch64 / Android API 31.

ART replacement now uses [dynamic symbols and runtime ABI probes](docs/art-compatibility.md), with no libart build-ID allowlist.

Android 17 has been adapted and verified on Pixel 7; the exact ART build, test
results and remaining scope are recorded in [docs/android17.md](docs/android17.md).

*Chinese version: [README_zh.md](README_zh.md)*

## Lifecycle

```text
ij2art inject
    └─ suspend all zygote threads
       ├─ register temporary scratch / memfd / dlopen handles
       ├─ dlopen carrier (the constructor only initializes; it installs no hooks)
       ├─ verify the GNU build-id → setup configures and installs GOT hooks
       └─ close temporary fds, release scratch → resume threads
             └─ fork / USAP specialization
                ├─ restore this process's GOT
                ├─ load payload when the process matches a target
                └─ original setcontext returns successfully → start control-ring worker
```

- The carrier and payload keep their linker registration: nothing is removed from
  `r_map`/solist, `dynstr` is not erased, and already-loaded libraries are not `munmap`ed.
  After a child process specializes, the carrier mappings stay until the process exits.
- `clear` suspends the parent zygote and its existing USAPs, confirms every GOT entry was
  restored, and then deregisters the carrier through a normal `dlclose`. If unloading fails
  it reports an error and keeps the mappings.
- A failed injection runs transactional cleanup: close fds, remove already-installed hooks,
  `dlclose`, release scratch. `targets` stops processes before atomically publishing the
  complete configuration, and rolls back to the previous configuration if the write fails.
- Existing USAPs are injected individually; new USAPs inherit from the parent zygote. A
  second `inject` checks for missing members and reports partial failure.

`common/hide_self.*`, `cli/src/hide.rs`, and `carrier/teardown_stub.S` are historical
experiment code that the current build does not use.

### Recovery rules for remote calls

Waiting uses a monotonic-clock deadline and `waitpid(WNOHANG)`; it does not rely on SIGALRM.
General-purpose registers, FP/SIMD, available SVE state, and the signal mask are saved and
restored; unsupported SME state is rejected before execution. The original execution
context is restored only after the function returns normally to the sentinel address (which
may raise SIGSEGV or SIGBUS — both require an exact PC match). A failed restore must never be
reported as success.

When a remote function crashes, times out, or fails to restore, all further remote calls are
forbidden, and the target is left in the SIGSTOP stopped state before detach. In that state
do not use SIGCONT or re-run `inject` to "recover" — inspect the site and, if necessary,
restart the target during a maintenance window. If the CLI is killed with SIGKILL or
otherwise cannot run cleanup, there is no automatic recovery guarantee.

## Build

```sh
./build.sh
```

Toolchain discovery is centralized in `sdk.env.sh`; the repository never hardcodes local
paths. It prefers the `SDK` / `NDK` / `BUILD_TOOLS` or `ANDROID_HOME` / `ANDROID_SDK_ROOT` /
`ANDROID_NDK_HOME` environment variables, then probes the standard locations
`~/Library/Android/sdk` and `~/Android/sdk`. NDK and build-tools default to the pinned
versions (28.1.13356709 / 36.0.0) and fall back to the highest installed version when
absent. The Rust `aarch64-linux-android` target is required; the cross linker comes from
`CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER`, exported by `sdk.env.sh` — source
`../sdk.env.sh` first when building inside `cli/` alone.

Artifacts: `out/ij2art`, `out/carrier.so` (with the payload embedded), and `out/payload.so`.
Use the GNU build-id to match a local artifact against a remote instance; never mix builds.
Building the Hook SDK additionally requires a JDK; `out/ij2art-hook-api.jar` is used to
compile replacement logic.

## Features and documentation

- **ART method hooking**: upload a replacement DEX to hook the entry of ordinary methods,
  `<init>` constructors, synchronized methods, and already-bound native methods. Supports
  `callOriginal`, logical deletion, live callback replacement through `hook update`, and
  methods with OAT quick code. Coverage level: `ENTRY_ONLY`.
- **Native inline hooking**: `ctl inline` uses the embedded ShadowHook v2.0.1 and supports
  arm64 function entry replacement, original-function trampolines, query, and removal.
  `ctl lib load` can pass a `.so` into the target process through the control ring, then
  dlopen it from a memfd, so no disk path is required.
- **JSON Java method calls**: `ctl java call` executes method calls described in JSON on the
  app main thread or on a new thread (for example, to enable WebView debugging). It is
  asynchronous and needs no ART hook. See [java-calls.md](docs/java-calls.md).
- **eBPF passive observation**: the `monitor` subcommand (P0: raw_syscalls) requires kernel
  ≥ 5.10; the CLI statically links the libbpf v1.7.0 ringbuf. See
  [ebpf-monitor.md](docs/ebpf-monitor.md).

### Documentation

English is the default for all documentation and code comments. Each document also has a
Chinese translation kept alongside it as `*_zh.md`, and the two versions are expected to be
updated together:

| English (default) | Chinese |
|---|---|
| [README.md](README.md) | [README_zh.md](README_zh.md) |
| [docs/ebpf-monitor.md](docs/ebpf-monitor.md) | [docs/ebpf-monitor_zh.md](docs/ebpf-monitor_zh.md) |
| [docs/java-calls.md](docs/java-calls.md) | [docs/java-calls_zh.md](docs/java-calls_zh.md) |
| [docs/android17.md](docs/android17.md) | [docs/android17_zh.md](docs/android17_zh.md) |

## Usage

```sh
# The deploy directory and file names are arbitrary (random names included): the CLI
# never reads its own file name, and the carrier is passed explicitly via --carrier.
adb push out/ij2art /data/local/tmp/deploy/cli
adb push out/carrier.so /data/local/tmp/deploy/
adb shell
su
cd /data/local/tmp/deploy
chmod +x cli

./cli inject --carrier ./carrier.so --targets com.example.target
./cli status
./cli launch com.example.target
./cli targets --targets com.a,com.b
./cli targets --none
./cli clear
```

`--all` (the default) matches processes whose `uid % 100000` falls in `[10000,20000)`; this
is not a SELinux domain check. The list is an exact match against the process name in the
specialization arguments, so an independent process such as `com.example.target:remote`
must be listed separately. On multi-zygote ROMs (for example OPPO/ColorOS
`zygote_ocomp`) the CLI picks the instance automatically from the target and prints its
reasoning to stderr; `--pid` overrides this. If targets span several zygotes it reports an
error and you must inject in separate passes.

Only processes started after injection are affected. `clear` does not unload the
carrier/payload from already-running apps; restart the app to clear them. The CLI, carrier,
and payload must come from the same build; before replacing artifacts, end the injection
session and restart the affected processes.

## Control ring

The payload creates a 64 KiB memfd, shares the command/response slots, and wakes the peer
with a shared futex; the CLI duplicates the fd with `pidfd_getfd` and maps the same file.
Only one protocol exists — there is no backward compatibility and no version negotiation;
the header `version` field is used only to strictly validate the current layout.

- The CLI holds a process-level exclusive `fcntl` write lock on the ring fd; other CLIs get
  a busy error.
- Every connection increments an independent 64-bit session number, and responses are
  validated against the session, the request sequence, and the command type.
- `cmd_seq != rsp_seq` means an older request is still in flight; a timeout or reconnect does
  not cancel it, and the command slot must not be overwritten.
- The worker copies a snapshot of the command before executing it, and publishes READY only
  after initialization completes.
- The CLI times out after 5 seconds by default; a single WRITE carries at most 3992 bytes,
  and a READ response at most 16344 bytes.

```sh
./cli ctl --pid P ping
./cli ctl --pid P mods
./cli ctl --pid P read 0xADDRESS 32
./cli ctl --pid P write 0xADDRESS deadbeef
./cli ctl --pid P call --in /libc.so getpid
./cli ctl --pid P shutdown
```

A SHUTDOWN response means the request was acknowledged; the worker then closes the fd,
unmaps the shared region, and exits, while the payload library stays loaded. CALL supports at
most 8 integer/pointer arguments, and an exception in the called function itself affects the
app; a CLI timeout does not mean the function was cancelled.

### Script / agent-friendly interface

`ctl` and status/inject/targets/clear/launch support `--json`: results are written to stdout
in a `{"ok":true,"data":...}` / `{"ok":false,"error":{...}}` envelope, while informational
messages stay on stderr. A single `ctl overview` connection returns the payload identity plus
snapshots of every registry; `ctl batch` reads JSON Lines from stdin and executes them in
bulk; `launch --wait N` and `ctl --pkg P --wait N` wait for a process to appear. The full
syntax and output contract are in `ij2art help` / `help ctl` / `help agent`.

## Regression tests

The suites are organized in four layers (Rust unit tests, host C++ unit tests,
isolated-process integration, on-device regressions); the matrix, prerequisites, and
per-feature commands are in [test/README.md](test/README.md).

```sh
# Host unit / shared-mapping / cross-process file-lock tests
cargo test --manifest-path cli/Cargo.toml --offline --locked

# Build the isolated Android test programs
./test/build-android.sh
```

`lifecycle-test <carrier.so> <payload.so>` performs 20 carrier load/enumerate/unload cycles
inside its own process, plus READY, PING, CALL, MODS, and SHUTDOWN tests against the real
payload. `remote-smoke <lifecycle-test>` only ptrace's the child process it starts itself,
verifies normal calls and the stop behavior after a timeout, and terminates and reaps that
child when it finishes. Neither takes over zygote or an existing app.
