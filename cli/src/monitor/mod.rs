//! eBPF passive observation, P0: raw_syscalls sys_enter/sys_exit.
//! These layout constants are mirrored on both sides with bpf/monitor.h, so any change must
//! be made on both sides at once (the same discipline as common/proto.h).
//! Events travel over a ringbuf; filtering happens in the kernel (tracked tgid plus the
//! policy nr) and enrichment happens here in the observing process.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod sys;
pub mod loader;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod ring;
pub mod view;
mod check;

pub const EVMAGIC: u32 = 0x31564E45; // "ENV1" in little-endian byte order
pub const EV_SYS_ENTER: u16 = 1;
pub const EV_SYS_EXIT: u16 = 2;
pub const EVF_TRUNCATED: u32 = 0x1;
pub const EVF_READ_FAIL: u32 = 0x2;

// policy action values; DROP (0) is implied by "not present in the policy table" rather than
// being stored, so it has no named constant here
pub const POL_HEAD: u8 = 1;
pub const POL_DECODE: u8 = 2;
// decoder types
pub const DEC_NONE: u8 = 0;
pub const DEC_PATH: u8 = 1;
pub const DEC_SOCKADDR: u8 = 2;

// cfg map slots
pub const CFG_PC_OFF: u32 = 0; // arm64 user pt_regs.pc (default 256)
pub const CFG_FP_OFF: u32 = 1; // arm64 user pt_regs.regs[29] fp (default 232)

// stats map slots: idx = kind*2 + (0 for emitted / 1 for dropped)
pub const STATS_SLOTS: u32 = 8;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvHdr {
    pub magic: u32,
    pub kind: u16,
    pub len: u16,
    pub cpu: u32,
    pub pid: u32,
    pub tid: u32,
    pub status: u32,
    pub ts_ns: u64,
    pub pc: u64,
    pub aux: u64,
}

#[repr(C)]
pub struct EvSys {
    pub hdr: EvHdr,      // 48
    pub args: [u64; 6],  // 96
    pub ret: i64,        // 104
    pub fp: [u64; 4],    // 136 caller lr chain; 0 means none or too shallow
    pub data_len: u16,   // 138
    pub data: [u8; 96],  // 234
    pub pad: [u8; 6],    // 240
}

/// arm64 user pt_regs offsets (see D3 in docs/ebpf-monitor.md; this is an on-device
/// verification item)
pub const ARM64_USER_PC_OFF: u64 = 256;
pub const ARM64_USER_FP_OFF: u64 = 232;

/// The embedded BPF object is copied by cli/build.rs from out/monitor.bpf.o. It is empty when
/// that file is missing, in which case the failure is reported at runtime.
static BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/monitor_bpf.o"));

// ---------------- CLI ----------------

pub fn cmd_monitor(args: &[String]) -> i32 {
    if has_flag(args, "--check") {
        return cmd_check();
    }
    let mut pids: Vec<i32> = Vec::new();
    let mut secs: Option<u64> = None;
    let mut json = false;
    let mut sys_all = false;
    let mut it = args.iter().skip(2);
    while let Some(w) = it.next() {
        match w.as_str() {
            "--pid" => match it.next().and_then(|v| v.parse().ok()) {
                Some(p) if p > 0 => pids.push(p),
                _ => {
                    eprintln!("[-] --pid requires a positive integer");
                    return 2;
                }
            },
            "--secs" => match it.next().and_then(|v| v.parse().ok()) {
                Some(s) => secs = Some(s),
                None => {
                    eprintln!("[-] --secs requires seconds");
                    return 2;
                }
            },
            "--json" => json = true,
            "--sys" => match it.next().map(|v| v.as_str()) {
                Some("all") => sys_all = true,
                Some("default") | None => {}
                _ => {
                    eprintln!("[-] --sys value: default | all");
                    return 2;
                }
            },
            _ => {
                eprintln!("[-] unknown argument {w}(see usage)");
                return 2;
            }
        }
    }
    if pids.is_empty() {
        eprintln!("[-] monitor requires --pid(--pkg discovery is P1 only)");
        return 2;
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("[-] requires root");
        return 1;
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        match run(&pids, secs, json, sys_all) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("[-] monitor: {e}");
                1
            }
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (pids, secs, json, sys_all);
        eprintln!("[-] monitor only supports Linux/Android");
        1
    }
}

fn has_flag(args: &[String], key: &str) -> bool {
    args.iter().any(|a| a == key)
}

// ---------------- monitor --check ----------------

fn cmd_check() -> i32 {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let mut ok = true;
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("[fail] not root");
            return 1;
        }
        // The kernel floor is 5.10 (D2/D3: probe_read_user/kernel, ringbuf, and bounded loops).
        let uts = uname_release();
        match kernel_floor_ok(&uts) {
            Ok(true) => println!("[ok] kernel {uts} (>= 5.10)"),
            Ok(false) => {
                println!("[fail] kernel {uts} < 5.10");
                ok = false;
            }
            Err(e) => {
                println!("[warn] kernel version parse failed: {e}(continuing)");
            }
        }
        match check::run(BPF_OBJECT) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[fail] end-to-end self-check: {e}");
                eprintln!("       if EPERM/EACCES, check root/SELinux bpf permission and avc denial");
                ok = false;
            }
        }
        if ok {
            println!("[+] check passed");
            0
        } else {
            1
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        eprintln!("[-] monitor only supports Linux/Android");
        1
    }
}

fn uname_release() -> String {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } != 0 {
            return String::new();
        }
        uts.release
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8 as char)
            .collect()
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        String::new()
    }
}

fn kernel_floor_ok(release: &str) -> Result<bool, String> {
    let mut it = release.split('.');
    let major: u32 = it
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or("missing major version")?;
    let minor: u32 = it
        .next()
        .and_then(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
        .ok_or("missing minor version")?;
    Ok((major, minor) >= (5, 10))
}

// ---------------- run main loop ----------------

#[cfg(any(target_os = "android", target_os = "linux"))]
fn run(
    pids: &[i32],
    secs: Option<u64>,
    json: bool,
    sys_all: bool,
) -> Result<i32, String> {
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    let (progs, maps) = load_programs(BPF_OBJECT, None)?;
    let events_fd = map_fd(&maps, "events_map")?;
    let attach = attach_all(&progs).map_err(|e| e.to_string())?;

    // Seed the cfg, policy, and tracked maps.
    seed_config(map_fd(&maps, "cfg_map")?)?;
    let policy_count = seed_policy(map_fd(&maps, "policy_map")?, sys_all)?;
    for pid in pids {
        let v: u32 = 1;
        sys::map_update_bytes(map_fd(&maps, "tracked_map")?, *pid as u32, &v.to_ne_bytes(), 0)
            .map_err(|e| format!("tracked write pid {pid}: {e}"))?;
        if std::path::Path::new(&format!("/proc/{pid}")).exists() {
            eprintln!("[*] tracking pid={pid} ({})", view::proc_comm(*pid));
        } else {
            eprintln!("[!] pid {pid} currently does not exist, keeping the tracking bit");
        }
    }

    let renderer = std::cell::RefCell::new(view::Renderer::new(json));
    let mut received = 0usize;
    let mut ringbuf = ring::RingBuf::new(events_fd, |rec| renderer.borrow_mut().render(rec))
        .map_err(|e| format!("libbpf ringbuf init: {e}"))?;
    let started = Instant::now();
    let deadline = secs.map(|s| started + Duration::from_secs(s));
    static RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
    unsafe {
        libc::signal(
            libc::SIGINT,
            signal_stop as extern "C" fn(libc::c_int) as libc::sighandler_t,
        );
    }
    extern "C" fn signal_stop(_: libc::c_int) {
        RUNNING.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    eprintln!(
        "[*] observing: {} pids, policy {} entries{} | Ctrl-C or --secs to stop",
        pids.len(),
        policy_count,
        if sys_all { " (all syscalls)" } else { "" }
    );
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    loop {
        if !RUNNING.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                break;
            }
        }
        received += ringbuf.poll(200)?;
        let buf = renderer.borrow_mut().take_output();
        if !buf.is_empty() {
            out.write_all(buf.as_bytes())
                .and_then(|_| out.flush())
                .map_err(|e| format!("stdout: {e}"))?;
        }
    }

    // Detach the probes first so the producers stop, then drain what is left in the buffer;
    // only then can the summary be reconciled against the user-space received count.
    drop(attach);
    loop {
        let n = ringbuf.consume()?;
        received += n;
        let buf = renderer.borrow_mut().take_output();
        out.write_all(buf.as_bytes()).map_err(|e| format!("stdout: {e}"))?;
        if n == 0 { break; }
    }
    out.flush().map_err(|e| format!("stdout: {e}"))?;
    // Summary: read the kernel-side per-kind counters directly.
    let stats = read_stats(map_fd(&maps, "stats_map")?)?;
    let dur = started.elapsed().as_secs_f64();
    eprintln!(
        "[summary] {dur:.1}s received={received} emitted: sys_enter={} sys_exit={} dropped: sys_enter={} sys_exit={}",
        stats[EV_SYS_ENTER as usize * 2],
        stats[EV_SYS_EXIT as usize * 2],
        stats[EV_SYS_ENTER as usize * 2 + 1],
        stats[EV_SYS_EXIT as usize * 2 + 1]
    );
    drop(ringbuf);
    drop(progs);
    drop(maps);
    Ok(0)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn seed_config(fd: i32) -> Result<(), String> {
    for (slot, val) in [(CFG_PC_OFF, ARM64_USER_PC_OFF), (CFG_FP_OFF, ARM64_USER_FP_OFF)] {
        sys::map_update_u64(fd, slot, val, 0).map_err(|e| format!("cfg write: {e}"))?;
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn read_stats(fd: i32) -> Result<[u64; STATS_SLOTS as usize], String> {
    let mut stats = [0u64; STATS_SLOTS as usize];
    for (i, value) in stats.iter_mut().enumerate() {
        *value = sys::map_lookup_u64(fd, i as u32).ok_or_else(|| format!("stats[{i}] read failed"))?;
    }
    Ok(stats)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn map_fd(
    maps: &[loader::LoadedMap],
    name: &str,
) -> Result<i32, String> {
    maps.iter()
        .find(|m| m.name == name)
        .and_then(|m| *m.fd.lock().ok()?)
        .ok_or_else(|| format!("missing map {name}"))
}

/// Default policy table: (nr, action, arg_idx, decoder, track_ret). The numbers are aarch64.
/// arg_idx selects the argument that DECODE reads; for PATH decoding, execve keeps its path in
/// args[0] while openat keeps it in args[1], so the two entries differ.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn seed_policy(fd: i32, sys_all: bool) -> Result<usize, String> {
    let mut base: Vec<(u32, u8, u8, u8, u8)> = vec![
        (56, POL_DECODE, 1, DEC_PATH, 1),
        (437, POL_DECODE, 1, DEC_PATH, 1),
        (221, POL_DECODE, 0, DEC_PATH, 0),
        (281, POL_DECODE, 1, DEC_PATH, 0),
        (78, POL_DECODE, 1, DEC_PATH, 0),
        (40, POL_HEAD, 0, DEC_NONE, 0),
        (203, POL_DECODE, 1, DEC_SOCKADDR, 1),
        (206, POL_DECODE, 4, DEC_SOCKADDR, 0),
        (211, POL_HEAD, 0, DEC_NONE, 0),
        (232, POL_HEAD, 0, DEC_NONE, 0),
        (117, POL_HEAD, 0, DEC_NONE, 0),
        (222, POL_HEAD, 0, DEC_NONE, 0),
        (226, POL_HEAD, 0, DEC_NONE, 0),
        (279, POL_DECODE, 0, DEC_PATH, 0),
        (270, POL_HEAD, 0, DEC_NONE, 0),
        (271, POL_HEAD, 0, DEC_NONE, 0),
        (146, POL_HEAD, 0, DEC_NONE, 0),
        (144, POL_HEAD, 0, DEC_NONE, 0),
        (145, POL_HEAD, 0, DEC_NONE, 0),
        (143, POL_HEAD, 0, DEC_NONE, 0),
        (147, POL_HEAD, 0, DEC_NONE, 0),
        (149, POL_HEAD, 0, DEC_NONE, 0),
        (159, POL_HEAD, 0, DEC_NONE, 0),
        (57, POL_HEAD, 0, DEC_NONE, 1),
        (23, POL_HEAD, 0, DEC_NONE, 1),
        (24, POL_HEAD, 0, DEC_NONE, 1),
        (436, POL_HEAD, 0, DEC_NONE, 1), // close_range (438 is pidfd_getfd)
    ];
    if sys_all {
        let covered: std::collections::HashSet<u32> = base.iter().map(|p| p.0).collect();
        for nr in 0u32..512 {
            if !covered.contains(&nr) {
                base.push((nr, POL_HEAD, 0, DEC_NONE, 0));
            }
        }
    }
    for (nr, action, arg_idx, decoder, track_ret) in base.iter() {
        let val = [*action, *arg_idx, 0u8 /* len_src is reserved */, *decoder, *track_ret, 0, 0, 0];
        sys::map_update_bytes(fd, *nr, &val, 0)
            .map_err(|e| format!("policy write nr {nr}: {e}"))?;
    }
    Ok(base.len())
}

// ---------------- load/attach ----------------

/// Returns the list of program fds and the list of maps. Each fd is kept inside a Mutex and is
/// closed by Drop.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn load_programs(
    object: &[u8],
    ring_size: Option<u32>,
) -> Result<
    (
        Vec<loader::ProgFd>,
        Vec<loader::LoadedMap>,
    ),
    String,
> {
    let parsed = loader::parse(object)?;
    let mut maps = Vec::new();
    for m in &parsed.maps {
        let max_entries = if m.name == "events_map" && m.map_type == sys::BPF_MAP_TYPE_RINGBUF {
            ring_size.unwrap_or(m.max_entries)
        } else {
            m.max_entries
        };
        let fd = sys::map_create(m.map_type, m.key_size, m.value_size, max_entries, m.map_flags)
            .map_err(|e| format!("create map {} failed: {e}", m.name))?;
        maps.push(loader::LoadedMap {
            name: m.name.clone(),
            fd: std::sync::Mutex::new(Some(fd)),
        });
    }
    let fd_of = |name: &str| -> Option<i32> {
        maps.iter()
            .find(|m| m.name == name)
            .and_then(|m| *m.fd.lock().ok()?)
    };
    let mut progs = Vec::new();
    for p in &parsed.progs {
        let mut insns = p.insns.clone();
        for (idx, map_name) in &p.relocs {
            let fd = fd_of(map_name).ok_or(format!("relocation target map does not exist: {map_name}"))?;
            loader::patch_map_fd(&mut insns, *idx, fd)?;
        }
        let fd = sys::prog_load(
            sys::BPF_PROG_TYPE_RAW_TRACEPOINT,
            // SAFETY: Insn is a flat, 8-byte repr(C) layout.
            unsafe {
                std::slice::from_raw_parts(insns.as_ptr() as *const u8, insns.len() * 8)
            },
            b"GPL\0",
        )
        .map_err(|e| format!("load {} failed: {}", p.section, e))?;
        progs.push(loader::ProgFd {
            section: p.section.clone(),
            fd: std::sync::Mutex::new(Some(fd)),
        });
    }
    Ok((progs, maps))
}

/// The raw tracepoint name is the section name with the "raw_tp/" prefix stripped off.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn attach_all(progs: &[loader::ProgFd]) -> Result<Vec<loader::RawTpLink>, std::io::Error> {
    let mut links = Vec::new();
    for p in progs {
        let name = p
            .section
            .strip_prefix("raw_tp/")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "unsupported section name"))?;
        let fd = p
            .fd
            .lock()
            .ok()
            .and_then(|g| *g)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "program fd is closed"))?;
        let link = sys::raw_tp_open(name, fd).map_err(|e| {
            std::io::Error::new(e.kind(), format!("attach {name}: {e}"))
        })?;
        links.push(loader::RawTpLink {
            fd: std::sync::Mutex::new(Some(link)),
        });
    }
    Ok(links)
}
