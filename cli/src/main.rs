// ij2art CLI -- a Frida-style one-shot injection tool with no daemon.
// Usage:
//   ij2art status [--carrier PATH]                      show zygote injection state
//   ij2art inject --carrier C.so [--all | --targets a,b,c]
//   ij2art targets [--carrier PATH] --all | --targets a,b,c | --none
//   ij2art launch <package>                             force-stop, then cold-start the target
//   ij2art ctl --pid P | --pkg NAME <action>            control ring RPC (see usage)
mod art;
mod ctl;
mod elf;
mod help;
mod inline;
mod java;
mod json;
mod loader;
mod monitor;
mod procfs;
mod proto;
mod remote;
mod resources;
mod state;

use json::Json;
use remote::{find_carrier, Remote};
use std::path::PathBuf;

const IDENT: &str = "ij2art-carrier/4"; // keep in sync with the carrier; bump on an ABI change
const DEFAULT_CARRIER: &str = "/data/local/tmp/ij2art/carrier.so";
// The memfd name masquerades as an entry that really exists in the system. The CLI tells
// carriers apart by the content identification string, never by the name.
const CARRIER_MEMFD_NAME: &str = "jit-zygote-cache";

const PROT_RW: u64 = 3; // PROT_READ|PROT_WRITE
const MAP_ANON_PRIV: u64 = 0x22; // MAP_PRIVATE|MAP_ANONYMOUS
const RTLD_NOW: u64 = 2;

fn main() {
    // println panics on EPIPE (which under panic=abort means SIGABRT), and that is the normal
    // case in pipelines (head/grep), so ignore it.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let args: Vec<String> = std::env::args().collect();
    // `ij2art <cmd> --help` is equivalent to `ij2art help <cmd>`
    if let Some(cmd) = args.get(1).map(|s| s.as_str()) {
        if cmd != "help" && args.get(2).is_some_and(|a| a == "--help" || a == "-h") {
            std::process::exit(help::cmd_help(&["ij2art".into(), "help".into(), cmd.into()]));
        }
    }
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("help") | Some("--help") | Some("-h") => help::cmd_help(&args),
        Some("status") => cmd_status(&args),
        Some("inject") => cmd_inject(&args),
        Some("targets") => cmd_targets(&args),
        Some("clear") => cmd_clear(&args),
        Some("launch") => cmd_launch(&args),
        Some("trace") => cmd_trace(&args),
        Some("monitor") => monitor::cmd_monitor(&args),
        Some("ctl") => ctl::run_ctl(&args),
        Some("zeromagic") => cmd_zeromagic(&args), // debug: zero magic to simulate a half-injection
        Some("rmap") => cmd_rmap(&args),           // debug: print the _r_debug r_map chain
        Some("elfdbg") => cmd_elfdbg(&args),       // debug: symbol/GOT resolution (file vs remote memory)
        _ => usage(),
    };
    std::process::exit(code);
}

fn usage() -> i32 {
    eprintln!(
        "ij2art -- Android ART / native injection and hook tool\n\
         usage: ij2art <status|inject|targets|clear|launch|monitor|ctl|trace> [options] [--json]\n\
         run ij2art help for full help; ij2art help <command> for one command's details"
    );
    2
}

fn opt_value(args: &[String], key: &str, default: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == key)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| default.to_string())
}

fn has_flag(args: &[String], key: &str) -> bool {
    args.iter().any(|a| a == key)
}

/// In --json mode, errors also go out in the JSON envelope (on stdout), while human mode
/// keeps writing text to stderr; the meaning of the exit codes is unchanged.
fn report_err(json: bool, msg: impl AsRef<str>, exit: i32) -> i32 {
    if json {
        println!("{}", json::err(None, msg.as_ref()));
    } else {
        eprintln!("[-] {}", msg.as_ref());
    }
    exit
}

fn pidof(pkg: &str) -> Option<i32> {
    let out = std::process::Command::new("pidof")
        .args(["-s", "--", pkg])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn parse_target_args(args: &[String]) -> (String, u32) {
    // returns (csv, flags); the default is --all
    if has_flag(args, "--none") {
        return (String::new(), 0);
    }
    if let Some(w) = args.windows(2).find(|w| w[0] == "--targets") {
        return (w[1].clone(), 0);
    }
    (String::new(), state::F_ALL_USER_APPS)
}

/// zygote selection: --pid overrides it explicitly (useful for precise control on ROMs with
/// several zygote instances); otherwise the zygote is auto-selected from the targets (see
/// procfs::choose_zygote), and the reason for the choice is printed to stderr.
fn pick_zygote(args: &[String]) -> Result<i32, String> {
    if let Some(w) = args.windows(2).find(|w| w[0] == "--pid") {
        return w[1].parse::<i32>().map_err(|_| format!("invalid --pid {}", w[1]));
    }
    let (csv, _) = parse_target_args(args);
    let targets: Vec<String> = csv
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let choice = procfs::choose_zygote(&targets)?;
    match choice.how {
        "target-parent" => {
            eprintln!("[*] target process running, auto-selecting its zygote pid={}", choice.pid)
        }
        "app-zygote" => eprintln!(
            "[*] multiple zygote instances detected, auto-selecting the normal-app zygote pid={} (--pid overrides)",
            choice.pid
        ),
        _ => {}
    }
    Ok(choice.pid)
}

// ---------------- status ----------------
fn cmd_status(args: &[String]) -> i32 {
    let json = has_flag(args, "--json");
    let carrier = PathBuf::from(opt_value(args, "--carrier", DEFAULT_CARRIER));
    let z = match pick_zygote(args) {
        Ok(z) => z,
        Err(e) => return report_err(json, e, 1),
    };
    match find_carrier(z, &carrier, IDENT) {
        Ok(Some((base, state_addr, _))) => {
            let Some(st): Option<state::State> = procfs::vm_read_struct(z, state_addr) else {
                return report_err(json, "found carrier but failed to read its state", 1);
            };
            if json {
                let all = st.flags & state::F_ALL_USER_APPS != 0;
                println!(
                    "{}",
                    json::ok(Json::Obj(vec![
                        ("pid".into(), Json::Int(z as i64)),
                        ("injected".into(), Json::Bool(true)),
                        ("carrier_base".into(), Json::hex(base)),
                        ("hook_installed".into(), Json::UInt(st.hook_installed as u64)),
                        ("version".into(), Json::UInt(st.version as u64)),
                        ("payload_fd".into(), Json::Int(st.payload_fd as i64)),
                        ("flags".into(), Json::hex(st.flags as u64)),
                        ("magic_ok".into(), Json::Bool(st.magic == state::MAGIC)),
                        ("self_handle".into(), Json::hex(st.self_handle)),
                        ("targets_all_user_apps".into(), Json::Bool(all)),
                        (
                            "targets".into(),
                            Json::Arr(if all {
                                Vec::new()
                            } else {
                                st.targets().into_iter().map(Json::text).collect()
                            }),
                        ),
                    ]))
                );
                return 0;
            }
            println!("[+] zygote pid={} injected with carrier @ {:#x}", z, base);
            println!("    hook_installed = {} (1=ok)", st.hook_installed);
            println!(
                "    version={} payload_fd={} flags={:#x} magic_ok={} self_handle={:#x}",
                st.version,
                st.payload_fd,
                st.flags,
                st.magic == state::MAGIC,
                st.self_handle
            );
            if st.flags & state::F_ALL_USER_APPS != 0 {
                println!("    targets = <all user apps>");
            } else {
                println!("    targets({}) = {:?}", st.targets_count, st.targets());
            }
            0
        }
        Ok(None) => {
            if json {
                println!(
                    "{}",
                    json::ok(Json::Obj(vec![
                        ("pid".into(), Json::Int(z as i64)),
                        ("injected".into(), Json::Bool(false)),
                    ]))
                );
            } else {
                println!("[-] zygote pid={} not injected", z);
            }
            1
        }
        Err(e) => report_err(json, format!("status: {}", e), 1),
    }
}

// ---------------- inject ----------------
fn cmd_inject(args: &[String]) -> i32 {
    let json = has_flag(args, "--json");
    let carrier = PathBuf::from(opt_value(args, "--carrier", DEFAULT_CARRIER));
    let (csv, flags) = parse_target_args(args);
    // the diagnostic log flag is not part of target selection; it is OR'd in separately
    // (see common/state.h IJ2ART_F_VERBOSE)
    let flags = flags | if has_flag(args, "--verbose") { state::F_VERBOSE } else { 0 };
    let force = has_flag(args, "--force");

    let zpid = match pick_zygote(args) {
        Ok(z) => z,
        Err(e) => return report_err(json, e, 1),
    };
    eprintln!("[*] target zygote pid={}", zpid);

    // reuse only a carrier whose full build identity matches; leave older versions untouched,
    // and never guess at their layout and then roll back
    let mut install_parent = true;
    let mut effective_csv = csv.clone();
    let mut effective_flags = flags;
    match remote::find_carrier_lenient(zpid, &carrier, IDENT) {
        Ok(Some(_)) => {
            let located = match find_carrier(zpid, &carrier, IDENT) {
                Ok(Some(v)) => v,
                Ok(None) => return report_err(json, "cannot verify carrier identity", 1),
                Err(e) => return report_err(json, e, 1),
            };
            let st = procfs::vm_read_struct::<state::State>(zpid, located.1);
            let healthy = st
                .map(|s| {
                    s.magic == state::MAGIC
                        && s.version == state::VERSION
                        && s.hook_installed & state::HOOK_OK != 0
                        && s.self_handle != 0
                        && s.scratch_addr == 0
                })
                .unwrap_or(false);
            if healthy && !force {
                let st = st.unwrap();
                effective_csv = st.targets().join(",");
                effective_flags = st.flags;
                install_parent = false;
                if !json {
                    println!("[=] zygote already injected, checking and filling in existing USAPs (targets can update the config)");
                }
            } else if let Err(e) = clear_family(zpid, &carrier) {
                return report_err(json, format!("rollback with the current build failed: {}", e), 1);
            }
        }
        Ok(None) => {}
        Err(e) => return report_err(json, format!("state check failed: {}", e), 1),
    }

    let Ok(carrier_bytes) = std::fs::read(&carrier) else {
        return report_err(json, format!("failed to read carrier: {}", carrier.display()), 1);
    };

    if install_parent {
        match inject_one(zpid, &carrier_bytes, &carrier, &csv, flags) {
            Ok(_) => {
                if !json {
                    println!("[+] zygote injection complete and verified")
                }
            }
            Err(e) => return report_err(json, format!("zygote injection failed: {}", e), 1),
        }
    }
    let mut failed = false;
    let mut usaps = Vec::new();

    // The USAP pool children that exist now were forked before injection, so they carry no
    // carrier -- inject each one of them. New pool members created later fork from the
    // injected zygote, so they inherit the hooks naturally.
    for upid in procfs::find_usaps_for(zpid) {
        match find_carrier(upid, &carrier, IDENT) {
            Ok(Some(_)) => continue, // already injected
            Ok(None) => {}
            Err(e) => {
                if json {
                    usaps.push(Json::Obj(vec![
                        ("pid".into(), Json::Int(upid as i64)),
                        ("ok".into(), Json::Bool(false)),
                        ("error".into(), Json::text(format!("identity check failed: {e}"))),
                    ]));
                } else {
                    eprintln!("[!] USAP {} identity check failed: {}", upid, e);
                }
                failed = true;
                continue;
            }
        }
        match inject_one(
            upid,
            &carrier_bytes,
            &carrier,
            &effective_csv,
            effective_flags,
        ) {
            Ok(_) => {
                if json {
                    usaps.push(Json::Obj(vec![
                        ("pid".into(), Json::Int(upid as i64)),
                        ("ok".into(), Json::Bool(true)),
                    ]));
                } else {
                    println!("[+] usap child process {} injected", upid);
                }
            }
            Err(e) => {
                if json {
                    usaps.push(Json::Obj(vec![
                        ("pid".into(), Json::Int(upid as i64)),
                        ("ok".into(), Json::Bool(false)),
                        ("error".into(), Json::text(e)),
                    ]));
                } else {
                    eprintln!("[!] USAP {} injection failed: {}", upid, e);
                }
                failed = true;
            }
        }
    }
    if json {
        println!(
            "{}",
            json::ok(Json::Obj(vec![
                ("zygote_pid".into(), Json::Int(zpid as i64)),
                ("zygote_injected".into(), Json::Bool(install_parent)),
                ("zygote_reused".into(), Json::Bool(!install_parent)),
                ("usaps".into(), Json::Arr(usaps)),
                ("ok".into(), Json::Bool(!failed)),
            ]))
        );
    }
    if failed {
        1
    } else {
        0
    }
}

/// Injection transaction: register every resource up front; on an ordinary failure, clean up
/// before detaching; do not keep making calls once the execution state is unknown.
fn inject_one(
    pid: i32,
    carrier_bytes: &[u8],
    carrier: &std::path::Path,
    csv: &str,
    flags: u32,
) -> Result<(), String> {
    // validate local artifacts and configuration before touching the remote side, so that
    // predictable errors do not land inside the hijack window
    validate_targets(csv)?;
    let setup_v = elf::sym_vaddr(carrier, "ij2art_setup").ok_or("carrier has no setup")?;
    let unhook_v = elf::sym_vaddr(carrier, "ij2art_unhook").ok_or("carrier has no unhook")?;
    let zmaps = procfs::maps(pid).map_err(|e| e.to_string())?;
    let (cp, cb) = procfs::lib_base(&zmaps, "/libc.so").ok_or("libc.so not found")?;
    let (lp, lb) = procfs::lib_base(&zmaps, "/linker64").ok_or("only 64-bit linker is supported")?;
    let (dp, db) = procfs::lib_base(&zmaps, "/libdl.so").ok_or("libdl.so not found")?;
    let syms = InjectSyms {
        mmap: resolve(pid, &cp, cb, "mmap"),
        write: resolve(pid, &cp, cb, "write"),
        memfd_create: resolve(pid, &cp, cb, "memfd_create"),
        close: resolve(pid, &cp, cb, "close"),
        munmap: resolve(pid, &cp, cb, "munmap"),
        dlopen: resolve(pid, &lp, lb, "__loader_android_dlopen_ext"),
        dlerror: resolve(pid, &lp, lb, "__loader_dlerror"),
        dlclose: resolve(pid, &lp, lb, "__loader_dlclose"),
        caller: resolve(pid, &dp, db, "dlopen"),
    };
    if [
        syms.mmap,
        syms.write,
        syms.memfd_create,
        syms.close,
        syms.munmap,
        syms.dlopen,
        syms.dlerror,
        syms.dlclose,
        syms.caller,
    ]
    .contains(&0)
    {
        return Err("symbol resolution failed".into());
    }
    let mut r = Remote::new(pid);
    let result = (|| {
        r.seize_all()?;
        if !procfs::is_unspecialized(pid) {
            return Err("process already specialized, aborting injection".into());
        }
        let mut owned = resources::Resources::default();
        let attempt = (|| {
            let scratch = r.call(
                syms.mmap,
                &[0, SCRATCH, PROT_RW, MAP_ANON_PRIV, u64::MAX, 0],
            )?;
            if scratch >= 0xffff_ffff_ffff_f000 {
                return Err("remote mmap failed".into());
            }
            owned.scratch = Some(scratch);
            let fd = push_file(&r, &syms, scratch, carrier_bytes, &mut owned)?;
            let path = format!("/proc/self/fd/{}\0", fd);
            vm_write_checked(pid, scratch, path.as_bytes())?;
            vm_write_checked(pid, scratch + 0x2000, &remote::library_fd_extinfo(fd))?;
            let handle = r.call(syms.dlopen, &[scratch, RTLD_NOW, scratch + 0x2000, syms.caller])?;
            if handle == 0 {
                let error = r.call(syms.dlerror, &[])?;
                let mut message = Vec::new();
                for offset in 0..512 {
                    let mut byte = [0];
                    if error == 0 || !procfs::vm_read(pid, error + offset, &mut byte) || byte[0] == 0 {
                        break;
                    }
                    message.push(byte[0]);
                }
                return Err(format!("android_dlopen_ext(carrier) returned NULL: {}", String::from_utf8_lossy(&message)));
            }
            owned.handle = Some(handle);
            // the ABI 4 constructor installs no hooks, so a failure before this point can
            // simply dlclose
            let (base, state_addr, _) =
                find_carrier(pid, carrier, IDENT)?.ok_or("loaded successfully but cannot verify carrier identity")?;
            owned.unhook = Some(base + unhook_v);
            vm_write_checked(pid, state_addr + state::OFF_HANDLE, &handle.to_ne_bytes())?;
            let csvz = format!("{}\0", csv);
            vm_write_checked(pid, scratch + 0x1000, csvz.as_bytes())?;
            // setup may install only some of the hooks; register it before entering, because
            // an ordinary failure must first unhook
            owned.armed = true;
            zero_result(
                r.call(base + setup_v, &[u64::MAX, scratch + 0x1000, flags as u64])?,
                "setup",
            )?;
            let st: state::State =
                procfs::vm_read_struct(pid, state_addr).ok_or("failed to read back state")?;
            if st.magic != state::MAGIC
                || st.version != state::VERSION
                || st.hook_installed & state::HOOK_OK == 0
                || st.scratch_addr != 0
            {
                return Err("carrier config/hook/resource ownership verification failed".into());
            }
            Ok(())
        })();
        r.reset_timeout(std::time::Duration::from_secs(10));
        let cleanup = owned.cleanup(&InjectOps { r: &r, syms: &syms }, attempt.is_err());
        if let Err(e) = cleanup {
            // a zygote that may still hold extra fds or be in an unknown remote-call state
            // must never be allowed to keep forking
            r.mark_unsafe();
            return Err(format!(
                "{}; cleanup failed: {}",
                attempt.err().unwrap_or_else(|| "injection transfer completed".into()),
                e
            ));
        }
        attempt
    })();
    r.finish(result)
}

struct InjectSyms {
    mmap: u64,
    write: u64,
    memfd_create: u64,
    close: u64,
    munmap: u64,
    dlopen: u64,
    dlerror: u64,
    dlclose: u64,
    caller: u64,
}
const SCRATCH: u64 = 0x10000;

fn zero_result(ret: u64, op: &str) -> Result<(), String> {
    if ret as i32 == 0 {
        Ok(())
    } else {
        Err(format!("{} returned {}", op, ret as i32))
    }
}
fn vm_write_checked(pid: i32, addr: u64, bytes: &[u8]) -> Result<(), String> {
    if procfs::vm_write(pid, addr, bytes) {
        Ok(())
    } else {
        Err(format!("failed to write remote memory {:#x}", addr))
    }
}

struct InjectOps<'a> {
    r: &'a Remote,
    syms: &'a InjectSyms,
}
impl resources::ResourceOps for InjectOps<'_> {
    fn close(&self, fd: i32) -> Result<(), String> {
        zero_result(self.r.call(self.syms.close, &[fd as u64])?, "close")
    }
    fn unhook(&self, addr: u64) -> Result<(), String> {
        zero_result(self.r.call(addr, &[])?, "unhook")
    }
    fn dlclose(&self, handle: u64) -> Result<(), String> {
        zero_result(self.r.call(self.syms.dlclose, &[handle])?, "dlclose")
    }
    fn munmap(&self, addr: u64) -> Result<(), String> {
        zero_result(
            self.r.call(self.syms.munmap, &[addr, SCRATCH])?,
            "munmap scratch",
        )
    }
    fn usable(&self) -> bool {
        self.r.usable()
    }
}

fn push_file(
    r: &Remote,
    syms: &InjectSyms,
    scratch: u64,
    bytes: &[u8],
    owned: &mut resources::Resources,
) -> Result<i32, String> {
    let name = format!("{}\0", CARRIER_MEMFD_NAME);
    vm_write_checked(r.pid, scratch + 0x8000, name.as_bytes())?;
    let fd = r.call(syms.memfd_create, &[scratch + 0x8000, 1 /* MFD_CLOEXEC */])? as i32;
    if fd < 0 {
        return Err("memfd_create failed".into());
    }
    owned.fd = Some(fd); // register it before the first write that may fail
    for chunk in bytes.chunks(0x4000) {
        vm_write_checked(r.pid, scratch, chunk)?;
        let mut off = 0;
        while off < chunk.len() {
            let n = r.call(
                syms.write,
                &[fd as u64, scratch + off as u64, (chunk.len() - off) as u64],
            )? as i64;
            if n <= 0 || n as usize > chunk.len() - off {
                return Err(format!("write returned {}", n));
            }
            off += n as usize;
        }
    }
    Ok(fd)
}

fn validate_targets(csv: &str) -> Result<(), String> {
    if csv.len() >= 2048 || csv.as_bytes().contains(&0) {
        return Err("targets must be under 2048 bytes total and contain no NUL".into());
    }
    let names: Vec<_> = csv.split(',').filter(|s| !s.is_empty()).collect();
    if names.len() > state::MAX_TARGETS || names.iter().any(|s| s.len() > 127) {
        return Err("targets allows at most 32 entries of at most 127 bytes each".into());
    }
    Ok(())
}

/// Stop the parent zygote first, then enumerate and stop its existing pool members. No new
/// copies are created for the entire duration of the update or cleanup.
fn stop_family(zpid: i32) -> Result<Vec<Remote>, String> {
    let mut parent = Remote::new(zpid);
    parent.seize_all()?;
    if !procfs::is_unspecialized(zpid) {
        return Err("target already specialized".into());
    }
    let mut family = vec![parent];
    for pid in procfs::find_usaps_for(zpid) {
        let mut r = Remote::new(pid);
        if let Err(e) = r.seize_all() {
            if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                continue;
            }
            return Err(e);
        }
        if procfs::is_usap_of(pid, zpid) {
            family.push(r);
        }
    }
    Ok(family)
}

// ---------------- targets ----------------
fn cmd_targets(args: &[String]) -> i32 {
    let json = has_flag(args, "--json");
    let carrier = PathBuf::from(opt_value(args, "--carrier", DEFAULT_CARRIER));
    let (csv, flags) = parse_target_args(args);
    let flags = flags | if has_flag(args, "--verbose") { state::F_VERBOSE } else { 0 };
    let zpid = match pick_zygote(args) {
        Ok(z) => z,
        Err(e) => return report_err(json, e, 1),
    };
    let result = (|| -> Result<usize, String> {
        validate_targets(&csv)?;
        let mut family = stop_family(zpid)?;
        let mut changes = Vec::new();
        for r in &family {
            let located = find_carrier(r.pid, &carrier, IDENT)?;
            let Some((_, addr, _)) = located else {
                if r.pid == zpid {
                    return Err("zygote not injected".into());
                }
                continue;
            };
            let old: state::State = procfs::vm_read_struct(r.pid, addr).ok_or("failed to read the original config")?;
            if old.version != state::VERSION || old.magic != state::MAGIC {
                return Err("an unfinished injection exists, aborting the update".into());
            }
            changes.push((r, addr + state::OFF_FLAGS, state::config_bytes(&old)));
        }
        let new = state::target_config(&csv, flags);
        let updates: Vec<_> = changes
            .iter()
            .map(|(r, addr, old)| (r.pid, *addr, old.clone()))
            .collect();
        let result = state::commit_configs(&updates, &new, |pid, addr, bytes| {
            procfs::vm_write(pid, addr, bytes)
        });
        if let Err(ref failure) = result {
            for (r, _, _) in &changes {
                if failure.unrestored.contains(&r.pid) {
                    r.mark_unsafe();
                }
            }
        }
        result.map_err(|e| e.message)?;
        let count = changes.len();
        drop(changes);
        for r in family.iter_mut().rev() {
            r.detach_all()?;
        }
        Ok(count)
    })();
    match result {
        Ok(n) => {
            if json {
                println!(
                    "{}",
                    json::ok(Json::Obj(vec![("updated".into(), Json::UInt(n as u64))]))
                );
            } else {
                println!("[+] targets atomically updated across {} processes", n);
            }
            0
        }
        Err(e) => report_err(json, format!("targets: {}", e), 1),
    }
}

// ---------------- clear ----------------
fn cmd_clear(args: &[String]) -> i32 {
    let json = has_flag(args, "--json");
    let carrier = PathBuf::from(opt_value(args, "--carrier", DEFAULT_CARRIER));
    // with --pid, clear only that instance; otherwise clear every injected zygote instance.
    // On a ROM with several zygotes the injector may have picked any of them, so pre-check
    // each one with maps, and never stop an instance that is not injected.
    let families: Vec<i32> = if let Some(w) = args.windows(2).find(|w| w[0] == "--pid") {
        match w[1].parse::<i32>() {
            Ok(p) => vec![p],
            Err(_) => return report_err(json, format!("invalid --pid {}", w[1]), 1),
        }
    } else {
        let candidates = procfs::zygote_candidates();
        if candidates.is_empty() {
            return report_err(json, "zygote not found", 1);
        }
        candidates
    };
    let mut total = 0usize;
    let mut errors = Vec::new();
    for zpid in families {
        match remote::find_carrier_lenient(zpid, &carrier, IDENT) {
            Ok(Some(_)) => match clear_family(zpid, &carrier) {
                Ok(n) => total += n,
                Err(e) => errors.push(format!("pid {zpid}: {e}")),
            },
            Ok(None) => {}
            Err(e) => errors.push(format!("pid {zpid}: state check failed: {e}")),
        }
    }
    if !errors.is_empty() {
        return report_err(json, format!("clear: {}", errors.join("; ")), 1);
    }
    if json {
        println!(
            "{}",
            json::ok(Json::Obj(vec![("cleared".into(), Json::UInt(total as u64))]))
        );
    } else {
        println!("[+] clear complete, {} processes handled", total);
    }
    0
}

fn clear_family(zpid: i32, carrier: &std::path::Path) -> Result<usize, String> {
    let mut family = stop_family(zpid)?;
    let mut cleared = 0;
    let mut errors = Vec::new();
    for r in &mut family {
        let result = (|| -> Result<bool, String> {
            // never read the new State from an unknown version, and never make guessed
            // modifications to the linker chain or to old mappings
            if remote::find_carrier_lenient(r.pid, carrier, IDENT)?.is_none() {
                return Ok(false);
            }
            let (base, state_addr, _) = find_carrier(r.pid, carrier, IDENT)?
                .ok_or("an old carrier cannot be safely unloaded by the current build; use the matching version")?;
            let st: state::State =
                procfs::vm_read_struct(r.pid, state_addr).ok_or("failed to read state")?;
            if st.version != state::VERSION || st.self_handle == 0 || st.scratch_addr != 0 {
                return Err("invalid carrier version/resource ownership, keeping the mappings".into());
            }
            let maps = procfs::maps(r.pid).map_err(|e| e.to_string())?;
            let (lp, lb) = procfs::lib_base(&maps, "/linker64").ok_or("linker64 not found")?;
            let dlclose = resolve(r.pid, &lp, lb, "__loader_dlclose");
            let unhook = elf::sym_vaddr(carrier, "ij2art_unhook").ok_or("no unhook")?;
            if dlclose == 0 {
                return Err("no dlclose".into());
            }
            r.reset_timeout(std::time::Duration::from_secs(25));
            zero_result(r.call(base + unhook, &[])?, "unhook")?;
            zero_result(r.call(dlclose, &[st.self_handle])?, "dlclose")?;
            if procfs::maps(r.pid)
                .map_err(|e| e.to_string())?
                .iter()
                .any(|m| m.start == base)
            {
                return Err("dlclose returned but the carrier is still referenced; keeping the mappings, not forcing munmap".into());
            }
            Ok(true)
        })();
        match result {
            Ok(true) => cleared += 1,
            Ok(false) => {}
            Err(e) => errors.push(format!("pid {}: {}", r.pid, e)),
        }
    }
    for r in family.iter_mut().rev() {
        if let Err(e) = r.detach_all() {
            errors.push(e);
        }
    }
    if errors.is_empty() {
        Ok(cleared)
    } else {
        Err(errors.join("; "))
    }
}

// ---------------- zeromagic (debug) ----------------
// Zero g_state.magic in the zygote to simulate a half-injection.
fn cmd_zeromagic(args: &[String]) -> i32 {
    let carrier = PathBuf::from(opt_value(args, "--carrier", DEFAULT_CARRIER));
    let zpid = match pick_zygote(args) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("[-] {e}");
            return 1;
        }
    };
    let Ok(Some((base, _, _))) = find_carrier(zpid, &carrier, IDENT) else {
        eprintln!("[-] not injected");
        return 1;
    };
    let Some(state_v) = elf::sym_vaddr(&carrier, "g_state") else {
        eprintln!("[-] no g_state symbol");
        return 1;
    };
    // magic sits at the end of the struct: size_of - 8
    let off = state_v + (core::mem::size_of::<state::State>() - 8) as u64;
    if procfs::vm_write(zpid, base + off, &0u64.to_ne_bytes()) {
        println!("[+] magic zeroed (simulating a half-injection)");
        0
    } else {
        eprintln!("[-] write failed");
        1
    }
}

// ---------------- rmap (debug) ----------------
// Walk the main executable's DT_DEBUG -> _r_debug and print the r_map chain.
fn cmd_rmap(args: &[String]) -> i32 {
    let pid = match pick_zygote(args) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("[-] {e} (specify with --pid)");
            return 1;
        }
    };
    let maps = procfs::maps(pid).expect("maps");
    let Some((exe_path, exe_base)) = maps
        .iter()
        .find(|m| m.off == 0 && m.path.ends_with("/app_process64"))
        .map(|m| (PathBuf::from(&m.path), m.start))
    else {
        eprintln!("[-] app_process64 not found");
        return 1;
    };
    // Read the exe header, then the phdrs, then PT_DYNAMIC, then DT_DEBUG. The linker fills in
    // the _r_debug address at runtime.
    let mut rd_addr: u64 = opt_value(args, "--rdebug", "0")
        .strip_prefix("0x")
        .map(|s| s.to_string())
        .and_then(|s| u64::from_str_radix(&s, 16).ok())
        .unwrap_or(0);
    if rd_addr != 0 {
        println!("[*] using the _r_debug given on the command line @ {:#x}", rd_addr);
    }
    let mut ehdr = [0u8; 64];
    if !procfs::vm_read(pid, exe_base, &mut ehdr) {
        eprintln!("[-] failed to read the exe header");
        return 1;
    }
    let phoff = u64::from_ne_bytes(ehdr[0x20..0x28].try_into().unwrap());
    let phentsize = u16::from_ne_bytes(ehdr[0x3A..0x3C].try_into().unwrap()) as u64;
    let phnum = u16::from_ne_bytes(ehdr[0x38..0x3A].try_into().unwrap()) as u64;
    let mut ph_found = false;
    'outer: for i in 0..phnum {
        let mut ph = [0u8; 56];
        if !procfs::vm_read(pid, exe_base + phoff + i * phentsize, &mut ph) {
            continue;
        }
        let p_type = u32::from_ne_bytes(ph[0..4].try_into().unwrap());
        if p_type != 2 {
            continue; // PT_DYNAMIC
        }
        ph_found = true;
        let p_vaddr = u64::from_ne_bytes(ph[16..24].try_into().unwrap());
        let p_filesz = u64::from_ne_bytes(ph[32..40].try_into().unwrap());
        for off in (0..p_filesz).step_by(16) {
            let mut de = [0u8; 16];
            if !procfs::vm_read(pid, exe_base + p_vaddr + off, &mut de) {
                continue;
            }
            let tag = u64::from_ne_bytes(de[0..8].try_into().unwrap()) as i64;
            if tag == 21 {
                // DT_DEBUG
                rd_addr = u64::from_ne_bytes(de[8..16].try_into().unwrap());
                break 'outer;
            }
            if tag == 0 {
                break;
            }
        }
    }
    if rd_addr == 0 {
        eprintln!(
            "[-] DT_DEBUG is empty (exe_base={:#x} phoff={:#x} phnum={} PT_DYNAMIC found={})",
            exe_base, phoff, phnum, ph_found
        );
        return 1;
    }
    println!("[*] _r_debug @ {:#x} (exe {})", rd_addr, exe_path.display());
    // r_map @ +8; link_map: l_addr@0 l_name@8 l_next@24
    let mut cur = [0u8; 8];
    if !procfs::vm_read(pid, rd_addr + 8, &mut cur) {
        eprintln!("[-] failed to read r_map");
        return 1;
    }
    let mut cur = u64::from_ne_bytes(cur) & !0xff00_0000_0000_0000;
    let mut n = 0;
    while cur != 0 && n < 1024 {
        let mut lm = [0u8; 40];
        if !procfs::vm_read(pid, cur, &mut lm) {
            println!("  #{n}  {cur:#x}  <unreadable>");
            break;
        }
        let l_addr = u64::from_ne_bytes(lm[0..8].try_into().unwrap());
        let l_name = u64::from_ne_bytes(lm[8..16].try_into().unwrap()) & !0xff00_0000_0000_0000;
        let l_next = u64::from_ne_bytes(lm[24..32].try_into().unwrap()) & !0xff00_0000_0000_0000;
        let mut name = [0u8; 128];
        let name_ok = l_name != 0 && procfs::vm_read(pid, l_name, &mut name);
        let name_str = if name_ok {
            let end = name.iter().position(|&b| b == 0).unwrap_or(128);
            String::from_utf8_lossy(&name[..end]).into_owned()
        } else {
            String::new()
        };
        println!("  #{n}  lm={cur:#x}  base={l_addr:#x}  {name_str}");
        cur = l_next;
        n += 1;
    }
    0
}

// ---------------- elfdbg (debug) ----------------
// Compare symbol/GOT resolution (file section headers / file PHDR / remote memory).
// Usage: elfdbg <so> <sym>          parse the disk file only (section headers first, PHDR fallback)
//        elfdbg --pid P <suffix> <sym>  parse the remote PT_DYNAMIC and compare it with the disk
fn cmd_elfdbg(args: &[String]) -> i32 {
    let mut pos: Vec<&String> = Vec::new();
    let mut skip_next = false;
    for a in args.iter().skip(2) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--pid" {
            skip_next = true;
            continue;
        }
        if !a.starts_with("--") {
            pos.push(a);
        }
    }
    let (Some(target), Some(sym)) = (pos.first(), pos.get(1)) else {
        eprintln!("usage: elfdbg [--pid P] <so path|path suffix> <symbol>");
        return 2;
    };
    if let Some(w) = args.windows(2).find(|w| w[0] == "--pid") {
        let Ok(pid) = w[1].parse::<i32>() else {
            eprintln!("[-] invalid pid");
            return 2;
        };
        let Ok(maps) = procfs::maps(pid) else {
            eprintln!("[-] failed to read maps");
            return 1;
        };
        let Some((path, base)) = procfs::lib_base(&maps, target) else {
            eprintln!("[-] {} not found in the maps of pid {}", target, pid);
            return 1;
        };
        println!("[*] remote pid={} {} base={:#x}", pid, path.display(), base);
        match elf::MemElf::load(pid, base) {
            Some(mut m) => {
                let sym_v = m.sym_addr(sym).map(|a| a - base);
                let slots = m
                    .reloc_slots(sym)
                    .map(|v| v.iter().map(|a| a - base).collect::<Vec<_>>());
                println!(
                    "    mem  sym = {}",
                    sym_v
                        .map(|v| format!("{:#x}", v))
                        .unwrap_or_else(|| "none".into())
                );
                println!("    mem  got = {:x?}", slots.unwrap_or_default());
            }
            None => println!("    mem  parse failed"),
        }
        let file_sym = elf::sym_vaddr(&path, sym);
        let file_got = elf::got_reloc_offsets_checked(&path, sym);
        println!(
            "    disk sym = {}",
            file_sym
                .map(|v| format!("{:#x}", v))
                .unwrap_or_else(|| "none".into())
        );
        println!("    disk got = {:x?}", file_got.unwrap_or_default());
        0
    } else {
        let path = PathBuf::from(target.as_str());
        let sym_v = elf::sym_vaddr(&path, sym);
        let got = elf::got_reloc_offsets_checked(&path, sym);
        println!("[*] file {}", path.display());
        println!(
            "    sym = {}",
            sym_v
                .map(|v| format!("{:#x}", v))
                .unwrap_or_else(|| "none".into())
        );
        if got.is_none() && sym_v.is_none() {
            eprintln!("[-] file parse failed (path/format problem)");
            println!("    got = <parse failed>");
            return 1;
        }
        println!("    got = {:x?}", got.unwrap_or_default());
        0
    }
}

// ---------------- trace (diagnostic) ----------------
// Watch the syscall sequence that runs during USAP specialization.
fn cmd_trace(args: &[String]) -> i32 {
    let secs: u32 = opt_value(args, "--secs", "25").parse().unwrap_or(25);
    let pids = procfs::find_usaps();
    if pids.is_empty() {
        eprintln!("[-] no usap pool processes");
        return 1;
    }
    println!("[*] tracing usap pool {:?}, window {}s", pids, secs);
    // syscalls we care about on aarch64: setresuid=147 setreuid=145 setresgid=149 setregid=143
    // setgroups=159 capset=91 prctl=167 openat=56 write=64 mount=40
    let interesting: Vec<u64> = vec![147, 145, 149, 143, 159, 91, 167, 56, 64, 40];
    let nr_name = |nr: u64| match nr {
        147 => "setresuid",
        145 => "setreuid",
        149 => "setresgid",
        143 => "setregid",
        159 => "setgroups",
        91 => "capset",
        167 => "prctl",
        56 => "openat",
        64 => "write",
        40 => "mount",
        _ => "?",
    };
    let r = remote::syscall_trace(&pids, secs, |ev, maps| {
        if !interesting.contains(&ev.nr) {
            return;
        }
        let lib = maps
            .iter()
            .find(|m| ev.pc >= m.start && ev.pc < m.end && m.flags.contains('x'))
            .and_then(|m| m.path.rsplit('/').next())
            .unwrap_or("??");
        // openat and write are too broad, so print only where they came from; print the
        // privilege-dropping calls in full
        println!(
            "[trace] pid={} {} pc={:#x} @ {}",
            ev.pid,
            nr_name(ev.nr),
            ev.pc,
            lib
        );
    });
    if let Err(e) = r {
        eprintln!("[-] trace: {}", e);
        return 1;
    }
    0
}

// ---------------- launch ----------------
fn cmd_launch(args: &[String]) -> i32 {
    let json = has_flag(args, "--json");
    let wait: u32 = opt_value(args, "--wait", "0").parse().unwrap_or(0);
    let Some(pkg) = args.get(2).filter(|a| !a.starts_with('-')) else {
        return report_err(json, "usage: launch <package> [--wait N] [--json]", 2);
    };
    if !pkg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
    {
        return report_err(json, "invalid package name", 1);
    }
    // force-stop guarantees a cold start and a re-fork from the zygote, so the process is
    // born with our hooks already in place
    let sh = format!(
        "am force-stop {0}; \
         C=$(cmd package resolve-activity --brief {0} | tail -n 1); \
         if [ -n \"$C\" ]; then am start -n \"$C\" >/dev/null && echo started: $C; \
         else echo 'no launchable activity, start it manually'; fi",
        pkg
    );
    let out = match std::process::Command::new("sh").arg("-c").arg(&sh).output() {
        Ok(o) if o.status.success() => o,
        _ => return report_err(json, "launch failed", 1),
    };
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let component = text
        .lines()
        .find_map(|l| l.strip_prefix("started: "))
        .map(str::to_owned);
    // --wait: poll until the process appears (a cold start plus AMS scheduling can take seconds)
    let mut pid = None;
    if component.is_some() {
        pid = pidof(pkg);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait as u64);
        while pid.is_none() && wait > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(500));
            pid = pidof(pkg);
        }
    }
    if json {
        println!(
            "{}",
            json::ok(Json::Obj(vec![
                ("package".into(), Json::text(pkg.clone())),
                (
                    "started".into(),
                    component.map(Json::text).unwrap_or(Json::Null),
                ),
                (
                    "pid".into(),
                    pid.map(|p| Json::Int(p as i64)).unwrap_or(Json::Null),
                ),
            ]))
        );
    } else {
        print!("{}", text);
        if wait > 0 {
            match pid {
                Some(p) => println!("[+] {} started, pid={}", pkg, p),
                None => eprintln!("[!] after waiting {}s, process {} was still not observed", wait, pkg),
            }
        }
    }
    0
}

// ---------------- small helpers ----------------
/// On-disk library symbol resolution (section headers first, PHDR fallback); if the disk
/// parse fails completely, fall back to the remote PT_DYNAMIC. Returns the runtime absolute
/// address, or 0 on failure.
fn resolve(pid: i32, lib_path: &std::path::Path, base: u64, name: &str) -> u64 {
    if let Some(v) = elf::sym_vaddr(lib_path, name) {
        return base + v;
    }
    elf::MemElf::load(pid, base)
        .and_then(|mut m| m.sym_addr(name))
        .unwrap_or(0)
}
