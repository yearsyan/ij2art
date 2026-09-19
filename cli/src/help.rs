//! Text for `ij2art help [topic]`. The audience includes both humans and LLM agents:
//! every command documents its syntax, semantics, output shape, and examples, while the agent
//! topic explains the --json and batch contracts in one place.

const OVERVIEW: &str = r#"ij2art -- Android ART / native injection and hooking tool
          (Frida-style one-shot injection, no daemon)

Usage
  ij2art <command> [options]
  ij2art help [topic]        show detailed help for one topic
  ij2art <command> --help    same as above

Commands
  status     show injection status for zygote (or the process given by --pid)
  inject     inject carrier into zygote and existing USAPs; reuse if already injected
  targets    atomically update the target list (--all / --targets a,b,c / --none)
  clear      clear injection (restore GOT + dlclose carrier)
  launch     cold-start the target app after force-stop; --wait N polls until it appears
  monitor    eBPF passive observation (own --json/--check; see docs/ebpf-monitor.md)
  ctl        control ring RPC: read/write memory, call functions, ART/native hooks, upload dex/so
  trace      debug: trace the syscall sequence during USAP specialization
  help       this help

Global flags
  --json     write results to stdout as a JSON envelope, human messages stay on stderr:
               success {"ok":true,"data":{...}}
               failure {"ok":false,"error":{"code":-44 or null,"message":"..."}}
             code is the payload status code (see help agent); exit-code semantics are unchanged.
  --help/-h  show help

Typical flow (requires root)
  adb push out/ij2art /data/local/tmp/ij2art-cli
  # On the device, chmod +x ij2art-cli and run as root:
  ./ij2art-cli inject --all
  ij2art launch com.example.app --wait 20
  ij2art ctl --pkg com.example.app ping

Exit codes
  0 success; 1 runtime error (target process/backend); 2 usage or argument error
  (no RPC submitted)

More topics
  ij2art help ctl        all control ring actions (inline/lib/dex/hook/overview/batch)
  ij2art help java       JSON Java method calls (main thread/new thread, no Java source parsing)
  ij2art help agent      output contract and best practices for scripts/LLM agents
  ij2art help inject     inject/status/targets/clear/launch in detail
  ij2art help debug      debug commands (zeromagic/rmap/elfdbg/trace)
Design docs are in the docs/ directory (ebpf-monitor.md, java-calls.md).
"#;

const CTL: &str = r#"ij2art ctl -- control ring RPC (shared-memory ring inside the target process;
              the process must already be injected)

Process selection
  --pid P          specify the process id directly
  --pkg NAME       resolve the package name via pidof; fail immediately if it is not running
  --wait N         with --pkg: poll up to N seconds for the process to appear
  --json           JSON envelope output (see help agent)

Observation
  ping                                      payload identity (python: data.pid/data.uid)
  mods                                      loaded module list (data.records[{base,name}])
  overview                                  snapshot of one connection: payload + proto version +
                                            inline/lib/dex/hook registries, to restore context
  read <hex-addr> <len>                     read memory (len <= 16344; data.hex is the result)
  write <hex-addr> <hexbytes>               write memory (<= 3992 bytes per call; read-only
                                            pages temporarily get W)
  call [--in LIB] <symbol|0xaddr> [a0..a7]  call a function in the target process (hex args;
                                            result in data.retval)
  shutdown                                  shut down the control ring worker (payload code is
                                            cleared on App restart)

native inline hook (ShadowHook; in-process native function replacement)
  inline init                          initialize the backend (idempotent; add auto-initializes)
  inline add --target T --replacement R [--in LIB] [--replacement-in LIB]
                                        [--original-slot SYM]
             T/R are 0x addresses or symbols; a symbol needs a module selector
             (the path suffix must match uniquely)
             --original-slot is the void* variable held by the proxy; the trampoline
             writes it before the hook takes effect
  inline list / query ID / del ID      records: {id,target,replacement,original,
                                       original_slot,state(ACTIVE|REMOVED|ERROR),
                                       backend_error}; del is a physical unhook and
                                       idempotent on success

instruction observation points (arm64; registers BEFORE executing the instruction)
  probe add --target ADDR/SYM [--in LIB] [--offset N]
  probe add --in LIB --offset RVA
             symbols require --in; an absolute 0x address must not use --in.
             module RVA means ELF virtual address + load bias, not file offset.
             --offset is added to a target when both are supplied; 4-byte aligned.
             optional: --tid T (0=any), --when xN=VALUE (x0..x30),
                       --max-hits N (0=unlimited; matching hits include dropped hits)
  probe list / query ID / del ID
             states ACTIVE / LIMITED / REMOVED / ERROR; LIMITED still has a patch.
             del physically restores the instruction: quiesce target callers first.
  probe read ID [--after SEQ] [--limit N]
             non-destructive batches (default/max 48); start at 0, then use next_seq.
             retains the latest 256 snapshots per probe, including after del.
             events: seq, hit, ts_ns (monotonic), tid, pc, sp, nzcv, regs.x0..x30.
             lost=overwritten since cursor; dropped=contended hits; more=next batch.
             busy (-75) is retryable with the same cursor. Maximum 64 installations
             per process lifetime; loaded ELFs only. Patches code using ShadowHook.

native library upload (a source for inline replacements)
  lib load <file.so> [--name N] [--nonce N]
             chunked upload of a .so (arm64 ELF64, <=4MiB) via memfd + dlopen; the
             record's module field "/memfd:NAME (deleted)" is usable directly as
             --in/--replacement-in
  lib list / commit ID / unload ID     unload is refused while an inline hook or an
                                       installed probe references the library; nonce supports resuming
                                       after a timeout (see the stderr hint)

ART method hook (Java method replacement; the app must register runtime readiness first)
  dex upload <file.dex> [--nonce N]               stdout: dex_id; upload to the app's private
                                                  InMemoryDexClassLoader
  dex upload --builtin tracer                     upload the embedded generic observation dex
                                                  (idempotent; nothing is injected beforehand)
  dex commit/query/list/del                       dex object management
  hook init                                       initialize the ART adapter (matched to libart)
  hook add --dex-id ID --target 'a.B.m(I)I'
           --replacement 'a.R.m(Lorg/ij2art/HookContext;)Ljava/lang/Object;'
           (or '--builtin tracer' instead of --replacement, after dex upload --builtin tracer)
  hook trace --target 'a.B.m(I)I'                 one-shot observation: init + builtin upload +
                                                  add in a single command; the tracer logs
                                                  args/result/exception/time/caller stack to
                                                  logcat tag ij2art.trace
  hook update ID --dex-id ID --replacement '...'  change the replacement of an existing hook
                                                  (also accepts '--builtin tracer')
  hook list / query ID / del ID                   del is a logical disable (physical restore is
                                                  unsupported)
  tracer records                                  read them with: adb logcat -s ij2art.trace:I
  custom replacement DEX (compiled on a host):    tools/hookproj.py ships in the release archive
                                                  and the source repository, self-contained
                                                  (the hook API JAR is embedded); init scaffolds a
                                                  project with the HookContext contract in
                                                  comments, build runs javac/jar/d8 (JDK +
                                                  Android SDK via --jdk/--sdk or auto-detect)
                                                  and prints the dex upload / hook add commands

Java method calls (JSON method calls only, no Java source; see ij2art help java)
  java call --thread main|new [--dex-id ID] (--request JSON | --file PATH)
             JSON: {"calls":[{"class":"a.B","method":"m","args":[{"type":"int","value":1}]}]}
             returns asynchronously with a job id/state; main=App main Looper,
             new=new daemon thread
  java query ID / list / del ID        query results/exceptions; del only deletes
                                       finished tasks

Batch mode
  ctl ... batch     read JSON Lines from stdin, one string array per line
                    (the argv of that action, without ctl itself); execute them
                    in order over one connection, one envelope per line:
                     ["ping"]
                     ["lib","load","/data/local/tmp/p.so","--name","p"]
                     ["inline","add","--target","0x...","--replacement","0x..."]
                    output: {"index":0,"ok":true,"data":{...}} one per line;
                    if any line fails the overall exit code is 1 and later lines
                    still run; batch cannot nest.
                    blank lines and lines starting with # are skipped.
"#;

const AGENT: &str = r#"ij2art -- output contract for scripts / LLM agents

1. Always pass --json. stdout is exactly one JSON envelope:
     {"ok":true,"data":{...}}                         success
     {"ok":false,"error":{"code":-44,"message":""}}   failure (code null means a local error)
   Informational messages (nonce, module selector, ...) go to stderr and never
   pollute stdout.
   Exit codes: 0 success / 1 runtime error / 2 usage error (no RPC submitted, safe to
   fix and retry).

2. Reduce adb round trips: use ctl batch for multi-step work (see help ctl). One
   adb shell can run the whole upload -> verify -> hook -> verify-again sequence.
   For plain observation of one Java method prefer `hook trace --target 'a.B.m(I)I'`:
   it needs no DEX file at all (the generic tracer is embedded in the CLI) and
   writes args/result/exception/time/caller stack to logcat tag ij2art.trace.
   Compile a custom replacement only when observation is not enough: get
   tools/hookproj.py from the release archive or the source repository, then on a
   host with a JDK and the Android SDK run init + build. init scaffolds the project
   (HookContext contract in comments); build resolves the toolchain via --jdk/--sdk
   flags, JAVA_HOME/ANDROID_HOME, or common install locations, and emits the exact
   dex upload / hook add commands to run on the device.

3. Restore context with ctl overview: one connection returns the payload identity,
   the protocol version, and every inline/probe/lib/dex/hook record, with no per-table queries.

4. Waiting for a process: after launch <pkg> --wait 20, go straight to
   ctl --pkg <pkg> --wait 20.

5. Idempotency and recovery:
   - dex upload / lib load use nonce as the idempotency key; after a timeout, rerun
     with the same nonce to resume (stderr prints the nonce), or query with
     dex query --nonce N / lib list and then commit.
   - inline/probe/lib/dex/hook list/query always return the final result of a timed-out
     operation; do not blindly retry install-type commands (adding a duplicate
     inline/probe target errors out -- a feature: it prevents stacked hooks).
   - probe read is non-destructive. Start with --after 0 and advance with next_seq;
     check lost and probe.dropped for missing observations. Retry -75 with the same
     cursor. LIMITED stops collection but requires probe del before shutdown/unload.
   - java call is an asynchronous submit; ok:true means only that the RPC succeeded,
     read data.state for the execution result. Poll query until SUCCEEDED/FAILED,
     then check results/error, and release the record slot with java del ID. A
     submit timeout does not mean cancellation: run java list/query first, and do
     not replay a method that may have side effects.

6. Payload status codes (error.code):
     -1 invalid command  -2 address unmapped/not writable  -3 length over limit
     -10..-19 ART/dex (argument/not ready/not found/state/limit/Java
              exception/unsupported/signature/busy)
     -40..-44 inline (argument/state/slot full/backend/not found)
     -50..-55 lib (argument/state/slot full/not found/dlopen failed/IO)
     -70..-75 probe (argument/state/slot full/backend/not found/buffer busy)
   Common recovery: for -44/-53 confirm the id with list; for -41/-51 read the hint
   in the message; for -43 check backend_error.

7. Stability contract: JSON field names and record field order stay stable; addresses
   are always "0x..." strings; read values by field name and never depend on text
   formatting. human-mode output is not guaranteed stable across versions.
"#;

const JAVA: &str = r#"ij2art ctl ... java -- describe Java method calls in JSON only

Syntax
  ctl --pid P [--json] java call --thread main|new [--dex-id ID]
                               (--request '<JSON>' | --file /path/calls.json)
  ctl --pid P [--json] java query ID
  ctl --pid P [--json] java list
  ctl --pid P [--json] java del ID
  --pkg NAME also selects an App. --file is a UTF-8 file on the device running the CLI.

Input contract
  Standard JSON only: no Java source, expressions, constructors, field reads/writes,
  loops, or branches.
  Format: {"calls":[{"class":"fully.qualified.Class","method":"method",
                     "args":[{"type":"declared type","value":value}]}]}
  class uses the Java binary name (use $ for inner classes); args may be omitted for
  no arguments.
  Every argument must give both type and value; the exact declared type selects the
  overload, with no type guessing.
  type: boolean/byte/short/char/int/long/float/double, a full wrapper class name,
        java.lang.String, or an array such as int[] / java.lang.String[].
  boolean uses true/false; integers are numbers within the type range; long also
  accepts a decimal string; float/double use finite numbers; char is exactly one
  UTF-16 unit; arrays use JSON arrays.
  Reference types accept null; other objects can only be passed through a
  {"ref":"name"} from a previous return value.
  Strings can be passed to compatible reference types such as
  String/CharSequence/Object.
  Static methods are called by default; instance methods need receiver:{"ref":"name"}.
  A call may add save:"name" to keep the returned object for later calls in the same
  request; args[].value also accepts ref.
  ref cannot cross tasks. Returned objects live only for that task.
  Unknown fields, duplicate fields, duplicate save, and forward ref are rejected.

Threads and ClassLoader
  --thread is required. main posts the whole call group to the App main Looper; new
  creates a new daemon thread (no Looper created). Calls in one request run in order
  and stop at the first exception; side effects already applied are not rolled back.
  Class initialization and method calls both happen on the selected thread. A long
  main-thread method still blocks the App UI.
  By default the built-in InMemoryDexClassLoader is used, whose parent is the
  ClassLoader registered by the App; --dex-id uses the InMemoryDexClassLoader created
  by dex upload, with parent-first delegation.
  The current thread's context ClassLoader is set temporarily during execution and
  restored afterwards.
  Requires App runtime readiness; no hook init and no libart build adaptation.
  Reflection attempts to reach non-public methods, but does not bypass Android hidden
  API/access restrictions.
  This is only a call description format, not a security sandbox; methods can produce
  ordinary App side effects.

Asynchronous results and limits
  call returns {id,dex_id,thread,state} immediately; query reports
  QUEUED/RUNNING/SUCCEEDED/FAILED.
  With --json, ok:true and exit code 0 mean the submit/query succeeded, not that the
  Java method ran successfully; data.state must be checked. On failure, error carries
  the zero-based call index and the exception type/message, and results keeps the
  earlier successful calls. list finds tasks after a submit timeout; a timeout does
  not cancel execution.
  Scalar results carry type/value; long is returned as a decimal string and non-finite
  floats as strings; objects/arrays return only class/opaque, with no implicit
  toString call and no field traversal.
  Strings return at most 512 UTF-16 units and the total result payload is capped at
  8192 bytes by default; a request may raise both per-job with "maxString" (64..15872)
  and "maxBytes" (512..15872) at the top level, e.g. {"calls":[...],"maxString":4096}.
  Truncation is flagged with truncated/omitted.
  Input is <=3992 UTF-8 bytes, 1..32 calls, JSON nesting <=16 levels, array types
  <=8 dimensions.
  At most 16 tasks are kept per process; release the record slot with java del ID
  after completion.
  Queued/running tasks cannot be deleted and also block dex del and shutdown; a Java
  method is never forcibly interrupted.
  shutdown stops admission of new tasks; on BUSY, retry after existing tasks finish.
  Completed tasks no longer hold DEX references.

Enabling WebView debugging (main thread, no dex upload)
  ij2art ctl --pkg com.example.app --json java call --thread main --request '{"calls":[
    {"class":"android.webkit.WebView","method":"setWebContentsDebuggingEnabled",
     "args":[{"type":"boolean","value":true}]}]}'
  ij2art ctl --pkg com.example.app --json java query <returned id>
  ij2art ctl --pkg com.example.app java del <returned id>

Chained instance calls (a static factory's return value as the receiver)
  {"calls":[
    {"class":"java.util.Locale","method":"getDefault","save":"locale"},
    {"class":"java.util.Locale","method":"getLanguage","receiver":{"ref":"locale"}}
  ]}
"#;

const INJECT: &str = r#"inject / status / targets / clear / launch

  ij2art inject [--carrier C.so] [--all | --targets a,b,c] [--force] [--verbose] [--pid P]
      inject the embedded carrier (with the payload inside) into zygote; also inject into every
      existing USAP pool member one by one.
      Reuse the existing injection when it is already injected and the build identity
      matches, only filling in missing USAPs; --force redoes it from scratch.
      --json outputs {"zygote_pid","zygote_injected","zygote_reused","usaps":[{pid,ok}]}.

  Carrier selection
      inject/status/targets/clear use the carrier embedded in this executable by default.
      No separate carrier.so or payload.so is required. --carrier PATH explicitly
      selects an external carrier for that command; use the same build for the whole
      session. Build identity checks also apply to embedded carriers.

  zygote auto-selection (multi-instance ROMs, e.g. OPPO's secondary zygote_ocomp):
    1. the target process is running -> its parent is the zygote that forked it
       (most authoritative);
    2. with multiple instances, exclude the main zygote that has a system_server
       child; ordinary third-party apps come from the secondary instance; if the
       targets span several zygotes, report an error;
    3. a single instance is used directly; otherwise fall back to the main zygote.
    The reasoning is printed to stderr; --pid overrides it explicitly (system apps
    and similar cases).

  ij2art status [--carrier PATH] [--pid P]
      show injection status; when not injected the exit code is 1 and the --json data
      is {"injected":false}.

  ij2art targets [--carrier PATH] [--pid P] (--all | --targets a,b,c | --none)
      atomically update the target list on zygote + existing USAPs; roll everything
      back on failure.

  ij2art clear [--carrier PATH] [--pid P]
      clear injection: restore GOT, dlclose carrier. Clean up inside the App first if
      there are active hooks.
      Without --pid, scan every zygote instance and clean all injected ones; instances
      that were not injected are left alone.

  ij2art launch <package> [--wait N]
      cold start after force-stop (re-fork from the injected zygote).
      --wait N: poll up to N seconds for the process to appear; --json data includes
      the started component name and pid.
"#;

const DEBUG: &str = r#"Debug commands (development only; output is not stable; --json unsupported)

  trace [--secs N]     observe the privilege-drop/mount syscall sequence during USAP
                       pool specialization
  zeromagic            zero g_state.magic in zygote to simulate a half-injected state
  rmap [--pid P]       print the main executable's DT_DEBUG -> _r_debug r_map chain
  elfdbg [--pid P] <so path|suffix> <symbol>
                       compare on-disk and remote-memory symbol/GOT resolution
"#;

pub fn cmd_help(args: &[String]) -> i32 {
    let topic = args.get(2).map(|s| s.as_str());
    let text = match topic {
        None => OVERVIEW,
        Some("ctl") => CTL,
        Some("java") => JAVA,
        Some("agent" | "json") => AGENT,
        Some("inject" | "status" | "targets" | "clear" | "launch") => INJECT,
        Some("debug" | "trace" | "zeromagic" | "rmap" | "elfdbg") => DEBUG,
        Some(other) => {
            eprintln!("[!] unknown help topic: {other}");
            OVERVIEW
        }
    };
    print!("{}", text);
    0
}
