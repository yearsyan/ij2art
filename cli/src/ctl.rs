// Control channel, CLI side: pick out the payload's control-ring memfd in the target process's
// fd table (confirmed by both size and magic number, since ART's own jit-cache memfd may exist
// in the same process); pidfd_getfd then duplicates an fd for the same file, and mapping it
// MAP_SHARED lets us operate on the same physical pages as the payload. The CLI disconnects as
// soon as it exits, while the worker goes back to sleep.
use crate::json::{self, Json};
use crate::proto;
use core::sync::atomic::{AtomicU32, Ordering};
use std::fs;
use std::time::{Duration, Instant};

// aarch64: pidfd_open=434, pidfd_getfd=438 (libc crate constants are unstable, so hardcode them)
const SYS_PIDFD_OPEN: libc::c_long = 434;
const SYS_PIDFD_GETFD: libc::c_long = 438;
#[cfg(any(target_os = "android", target_os = "linux"))]
const FUTEX_WAIT: libc::c_int = 0;
#[cfg(any(target_os = "android", target_os = "linux"))]
const FUTEX_WAKE: libc::c_int = 1;

/// Dual output for every ctl action: `human` keeps the existing byte-exact text, and `data`
/// is what --json and batch consume. `exit` lets actions that can partially fail, such as
/// batch, return a nonzero code; regular actions always exit 0.
pub(crate) struct Outcome {
    pub human: String,
    pub data: Json,
    pub exit: i32,
}
impl Outcome {
    pub(crate) fn new(human: impl Into<String>, data: Json) -> Self {
        Self {
            human: human.into(),
            data,
            exit: 0,
        }
    }
}

fn fail(json: bool, code: Option<i32>, msg: &str, exit: i32) -> i32 {
    if json {
        println!("{}", json::err(code, msg));
    } else {
        eprintln!("[-] {}", msg);
    }
    exit
}

/// The error text that check_status produces is a contract ("payload status=N: ..."); --json
/// relies on it to extract the error code.
fn payload_code(msg: &str) -> Option<i32> {
    let rest = msg.strip_prefix("payload status=")?;
    let num: String = rest
        .chars()
        .take_while(|c| *c == '-' || c.is_ascii_digit())
        .collect();
    num.parse().ok()
}

pub fn run_ctl(args: &[String]) -> i32 {
    let json = args.iter().any(|a| a == "--json");
    let (args, wait) = match clean_args(args) {
        Ok(v) => v,
        Err(e) => return fail(json, None, &e, 2),
    };
    let Some(pid) = resolve_pid(&args, wait) else {
        return fail(
            json,
            None,
            "need --pid P or --pkg NAME (with --pkg the process must already be running, or use --wait N)",
            2,
        );
    };
    // Parse the command before opening the ring, so a malformed command never submits an RPC.
    let plan = match plan(&args) {
        Ok(p) => p,
        Err(e) => return fail(json, None, &e, 2),
    };
    let mut ring = match Ring::open(pid) {
        Ok(r) => r,
        Err(e) => return fail(json, None, &format!("pid {}: {}", pid, e), 1),
    };
    match execute(plan, &args, &mut ring) {
        Ok(outcome) => {
            if json {
                println!("{}", json::ok(outcome.data));
            } else if !outcome.human.is_empty() {
                print!("{}", outcome.human);
            }
            outcome.exit
        }
        Err(e) => fail(json, payload_code(&e), &e, 1),
    }
}

// ---------------- process lookup ----------------
fn resolve_pid(args: &[String], wait_secs: u32) -> Option<i32> {
    if let Some(w) = args.windows(2).find(|w| w[0] == "--pid") {
        if let Ok(p) = w[1].parse() {
            return Some(p);
        }
    }
    if let Some(w) = args.windows(2).find(|w| w[0] == "--pkg") {
        let deadline = Instant::now() + Duration::from_secs(wait_secs as u64);
        loop {
            let out = std::process::Command::new("pidof")
                .args(["-s", "--", &w[1]])
                .output()
                .ok()?;
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if let Ok(p) = s.parse() {
                return Some(p);
            }
            if wait_secs == 0 || Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    None
}

/// Strip the global flags (--json / --wait N) so each subcommand parser sees only its own syntax.
fn clean_args(args: &[String]) -> Result<(Vec<String>, u32), String> {
    let mut out = Vec::with_capacity(args.len());
    let mut wait = 0u32;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => {}
            "--wait" => {
                let v = it.next().ok_or("--wait needs a seconds value")?;
                wait = v.parse().map_err(|_| format!("invalid --wait seconds: {v}"))?;
            }
            _ => out.push(a.clone()),
        }
    }
    Ok((out, wait))
}

/// positional arguments left after skipping the subcommand name and the value-taking flags
fn positionals(args: &[String]) -> Vec<String> {
    let value_flags = ["--pid", "--pkg", "--in"];
    let mut out = Vec::new();
    let mut skip_next = false;
    for a in args.iter().skip(2) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if value_flags.contains(&a.as_str()) {
            skip_next = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        out.push(a.clone());
    }
    out
}

enum Plan {
    Art(crate::art::Command),
    Java(crate::java::Command),
    Inline(crate::inline::Command),
    Probe(crate::probe::Command),
    Lib(crate::loader::Command),
    Basic(String),
}
fn plan(args: &[String]) -> Result<Plan, String> {
    let pos = positionals(args);
    let Some(action) = pos.first().map(|s| s.as_str()) else {
        return Err(
            "missing action: ping | mods | read | write | call | java | dex | hook | inline | probe | lib | overview | batch | shutdown"
                .into(),
        );
    };
    Ok(match action {
        "dex" | "hook" => Plan::Art(crate::art::Command::parse(args)?),
        "java" => Plan::Java(crate::java::Command::parse(args)?),
        "inline" => Plan::Inline(crate::inline::Command::parse(args)?),
        "probe" => Plan::Probe(crate::probe::Command::parse(args)?),
        "lib" => Plan::Lib(crate::loader::Command::parse(args)?),
        "ping" | "mods" | "read" | "write" | "call" | "shutdown" | "overview" | "batch" => {
            Plan::Basic(action.into())
        }
        other => return Err(format!("unknown action {other} (see ij2art help ctl)")),
    })
}

fn execute(plan: Plan, args: &[String], ring: &mut Ring) -> Result<Outcome, String> {
    match plan {
        Plan::Art(c) => c.run(ring),
        Plan::Java(c) => c.run(ring),
        Plan::Inline(c) => c.run(ring),
        Plan::Probe(c) => c.run(ring),
        Plan::Lib(c) => c.run(ring),
        Plan::Basic(action) => {
            let pos = positionals(args);
            match action.as_str() {
                "ping" => do_ping(ring),
                "mods" => do_mods(ring),
                "read" if pos.len() >= 3 => do_read(ring, &pos[1], &pos[2]),
                "write" if pos.len() >= 3 => do_write(ring, &pos[1], &pos[2..]),
                "call" if pos.len() >= 2 => do_call(ring, ring.pid, &pos[1..], args),
                "overview" => do_overview(ring),
                "batch" => do_batch(ring),
                "shutdown" => do_shutdown(ring),
                a => Err(format!("action {a} has too few arguments (see ij2art help ctl)")),
            }
        }
    }
}

/// Single-connection batch mode: each line of stdin is a JSON string array (that line's argv,
/// without `ctl` itself), and each line emits one {"index","ok","data"|"error"} envelope. If
/// any line fails, the overall exit code becomes 1.
fn do_batch(ring: &mut Ring) -> Result<Outcome, String> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("reading batch stdin: {e}"))?;
    let mut results = Vec::new();
    let mut human = String::new();
    let mut failed = 0u64;
    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let outcome = json::parse_argv_line(line).and_then(|words| {
            let mut argv = vec!["ij2art".to_string(), "ctl".to_string()];
            argv.extend(words);
            let (argv, _) = clean_args(&argv)?;
            if positionals(&argv).first().map(String::as_str) == Some("batch") {
                return Err("batch cannot be nested".into());
            }
            plan(&argv).and_then(|p| execute(p, &argv, ring))
        });
        let mut fields = vec![
            ("index".into(), Json::UInt(index as u64)),
            ("ok".into(), Json::Bool(outcome.is_ok())),
        ];
        match outcome {
            Ok(o) => fields.push(("data".into(), o.data)),
            Err(e) => {
                failed += 1;
                let code = payload_code(&e)
                    .map(|c| Json::Int(c as i64))
                    .unwrap_or(Json::Null);
                fields.push((
                    "error".into(),
                    Json::Obj(vec![("code".into(), code), ("message".into(), Json::text(e))]),
                ));
            }
        }
        let envelope = Json::Obj(fields).to_string();
        human.push_str(&envelope);
        human.push('\n');
        results.push(Json::Raw(envelope));
    }
    let mut out = Outcome::new(
        human,
        Json::Obj(vec![
            ("results".into(), Json::Arr(results)),
            ("failed".into(), Json::UInt(failed)),
        ]),
    );
    out.exit = (failed > 0) as i32;
    Ok(out)
}

/// A full snapshot taken over one connection: the payload identity plus the four registries,
/// used to restore context.
fn do_overview(ring: &mut Ring) -> Result<Outcome, String> {
    let pong = do_ping(ring)?;
    let inline = ring.rpc(|c| wr32(c, proto::C_TYPE, crate::inline::LIST))?;
    check_status(&inline)?;
    let inline_records = crate::inline::decode(&inline.data)?;
    let probes = ring.rpc(|c| wr32(c, proto::C_TYPE, crate::probe::LIST))?;
    check_status(&probes)?;
    let probe_records = crate::probe::decode(&probes.data)?;
    let lib = crate::art::request(ring, crate::loader::LIST, 0, 0, &[])?;
    let lib_records = crate::loader::list_json(&lib.data)?;
    let dex = crate::art::request(ring, crate::art::DEX_LIST, 0, 0, &[])?;
    if dex.data.len() % crate::art::DEX_INFO_SIZE != 0 {
        return Err("invalid/truncated DEX list".into());
    }
    let dex_records: Vec<Json> = dex
        .data
        .chunks_exact(crate::art::DEX_INFO_SIZE)
        .map(crate::art::dex_json)
        .collect::<Result<_, _>>()?;
    let hook = crate::art::request(ring, crate::art::HOOK_LIST, 0, 0, &[])?;
    let mut hook_records = Vec::new();
    let mut at = 0;
    while at < hook.data.len() {
        let (record, used) = crate::art::decode_hook_json(&hook.data[at..])?;
        hook_records.push(record);
        at += used;
    }
    let section = |records: Vec<Json>, truncated: bool| {
        Json::Obj(vec![
            ("count".into(), Json::UInt(records.len() as u64)),
            ("truncated".into(), Json::Bool(truncated)),
            ("records".into(), Json::Arr(records)),
        ])
    };
    let data = Json::Obj(vec![
        ("proto".into(), Json::UInt(proto::PROTO_VER as u64)),
        ("payload".into(), pong.data),
        ("inline".into(), section(inline_records, false)),
        ("probe".into(), section(probe_records, false)),
        ("lib".into(), section(lib_records, lib.flags & 1 != 0)),
        ("dex".into(), section(dex_records, dex.flags & 1 != 0)),
        (
            "hook".into(),
            section(hook_records, hook.flags & 1 != 0),
        ),
    ]);
    let counts = |name: &str| match &data {
        Json::Obj(fields) => fields
            .iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| match v {
                Json::Obj(f) => f.iter().find(|(k, _)| k == "count").and_then(|(_, v)| match v {
                    Json::UInt(n) => Some(*n),
                    _ => None,
                }),
                _ => None,
            })
            .unwrap_or(0),
        _ => 0,
    };
    let human = format!(
        "payload: {} (proto {})\ninline: {}  probe: {}  lib: {}  dex: {}  hook: {}\n",
        match &data {
            Json::Obj(f) => match f.iter().find(|(k, _)| k == "payload").map(|(_, v)| v) {
                Some(Json::Obj(p)) => match p.iter().find(|(k, _)| k == "message").map(|(_, v)| v) {
                    Some(Json::Str(s)) => s.clone(),
                    _ => "?".into(),
                },
                _ => "?".into(),
            },
            _ => "?".into(),
        },
        proto::PROTO_VER,
        counts("inline"),
        counts("probe"),
        counts("lib"),
        counts("dex"),
        counts("hook"),
    );
    Ok(Outcome::new(human, data))
}

fn opt_value(args: &[String], key: &str, default: &str) -> String {
    args.windows(2)
        .find(|w| w[0] == key)
        .map(|w| w[1].clone())
        .unwrap_or_else(|| default.to_string())
}

// ---------------- shared ring connection and RPC ----------------
#[derive(Debug)]
pub struct Response {
    pub status: i32,
    pub flags: u32,
    pub retval: u64,
    pub len: usize,
    pub data: Vec<u8>,
}

pub struct Ring {
    map: *mut u8,
    // the fcntl lock is owned by the process, so the fd has to be held until the connection
    // ends; flock on a shared OFD cannot be used here
    _fd: std::os::fd::OwnedFd,
    session: u64,
    pub pid: i32, // hook init needs to resolve libart symbols on a per-process basis
}
unsafe impl Send for Ring {}

impl Ring {
    pub fn open(pid: i32) -> Result<Ring, String> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        if !cfg!(any(target_os = "android", target_os = "linux")) {
            return Err("controlling a remote process requires Android/Linux".into());
        }
        unsafe {
            let p = libc::syscall(SYS_PIDFD_OPEN as _, pid, 0u32);
            if p < 0 {
                return Err(format!("pidfd_open: {}", errno_s()));
            }
            let pidfd = OwnedFd::from_raw_fd(p as i32);
            let dir = fs::read_dir(format!("/proc/{}/fd", pid)).map_err(|e| e.to_string())?;
            for ent in dir.flatten() {
                let Ok(link) = fs::read_link(ent.path()) else {
                    continue;
                };
                if !link.to_string_lossy().starts_with("/memfd:jit-cache") {
                    continue;
                }
                let Some(tfd) = ent.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                    continue;
                };
                let dup = libc::syscall(SYS_PIDFD_GETFD as _, pidfd.as_raw_fd(), tfd, 0u32);
                if dup < 0 {
                    continue;
                }
                let fd = OwnedFd::from_raw_fd(dup as i32);
                if looks_like_ring(fd.as_raw_fd()) {
                    return Self::from_fd(fd, pid);
                }
            }
            Err("no ready control ring matching the current CLI layout found".into())
        }
    }

    fn from_fd(fd: std::os::fd::OwnedFd, pid: i32) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        unsafe {
            let mut lock: libc::flock = core::mem::zeroed();
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            lock.l_start = 0;
            lock.l_len = 0;
            if libc::fcntl(fd.as_raw_fd(), libc::F_SETLK, &lock) < 0 {
                return Err(format!(
                    "control ring is busy with another CLI or does not support file locks: {}",
                    errno_s()
                ));
            }
            if !looks_like_ring(fd.as_raw_fd()) {
                return Err("control ring not ready or memory layout mismatch".into());
            }
            let map = libc::mmap(
                core::ptr::null_mut(),
                proto::RING_FDSIZE as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            );
            if map == libc::MAP_FAILED {
                return Err(format!("mmap: {}", errno_s()));
            }
            let mut ring = Self {
                map: map.cast(),
                _fd: fd,
                session: 0,
                pid,
            };
            let hdr = core::slice::from_raw_parts(ring.map, 128);
            if rd32(hdr, proto::H_PID) as i32 != pid {
                return Err("control ring process identity mismatch".into());
            }
            ring.ensure_ready()?;
            let sessions = &*(ring.map.add(proto::H_SESS) as *const core::sync::atomic::AtomicU64);
            ring.session = sessions
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
                .map_err(|_| "session numbers exhausted, re-establish the control ring")?
                + 1;
            Ok(ring)
        }
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        unsafe { &*(self.map.add(off) as *const AtomicU32) }
    }
    fn ensure_ready(&self) -> Result<(), String> {
        let flags = self.word(proto::H_FLAGS).load(Ordering::Acquire);
        if flags & proto::RMF_SHUTDOWN != 0 {
            return Err("control ring is shutting down, cannot send new commands".into());
        }
        if flags & proto::RMF_WORKER == 0 {
            return Err("worker not ready".into());
        }
        Ok(())
    }
    pub fn rpc(&mut self, fill: impl FnOnce(&mut [u8])) -> Result<Response, String> {
        self.rpc_timeout(fill, Duration::from_secs(5))
    }
    fn rpc_timeout(
        &mut self,
        fill: impl FnOnce(&mut [u8]),
        timeout: Duration,
    ) -> Result<Response, String> {
        let deadline = Instant::now() + timeout;
        // when the client exits it frees only the connection lock, not a request that has
        // already been published; a new connection first waits for the old request to be consumed
        let previous = loop {
            self.ensure_ready()?;
            let cmd = self.word(proto::H_CMD_SEQ).load(Ordering::Acquire);
            let rsp = self.word(proto::H_RSP_SEQ).load(Ordering::Acquire);
            if cmd == rsp {
                break cmd;
            }
            wait_word(self.word(proto::H_RSP_SEQ), rsp, deadline)?;
        };
        // the fill operation works on its own buffer, so a parse failure before publishing
        // cannot pollute the shared command
        let mut bytes = [0u8; 0x1000];
        fill(&mut bytes);
        let kind = rd32(&bytes, proto::C_TYPE);
        let id = previous.wrapping_add(1);
        wr32(&mut bytes, proto::C_ID, id);
        wr64(&mut bytes, proto::C_SESS, self.session);
        self.ensure_ready()?;
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.map.add(proto::CMD_OFF),
                bytes.len(),
            );
        }
        self.word(proto::H_CMD_SEQ).store(id, Ordering::Release);
        wake_word(self.word(proto::H_CMD_SEQ));
        loop {
            let seq = self.word(proto::H_RSP_SEQ).load(Ordering::Acquire);
            if seq == id {
                let rsp =
                    unsafe { core::slice::from_raw_parts(self.map.add(proto::RSP_OFF), 0x4000) };
                if rd32(rsp, proto::R_ID) != id
                    || rd32(rsp, proto::R_TYPE) != kind
                    || rd64(rsp, proto::R_SESSION) != self.session
                {
                    return Err("response identity mismatch (seq/type/session), response not accepted".into());
                }
                let len = rd64(rsp, proto::R_LEN) as usize;
                if len > proto::RSP_DATA_MAX {
                    return Err("invalid response length".into());
                }
                return Ok(Response {
                    status: rd32(rsp, proto::R_STATUS) as i32,
                    flags: rd32(rsp, proto::R_FLAGS),
                    retval: rd64(rsp, proto::R_RETVAL),
                    len,
                    data: rsp[proto::R_DATA..proto::R_DATA + len].to_vec(),
                });
            }
            wait_word(self.word(proto::H_RSP_SEQ), seq, deadline)?;
        }
    }
}
impl Drop for Ring {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.map.cast(), proto::RING_FDSIZE as usize);
        }
    }
}

fn wait_word(word: &AtomicU32, expected: u32, deadline: Instant) -> Result<(), String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("timed out waiting for the response; the published request is still in flight and will not be cancelled or overwritten".into());
    }
    let remain = (deadline - now).min(Duration::from_millis(100));
    #[cfg(any(target_os = "android", target_os = "linux"))]
    unsafe {
        let ts = libc::timespec {
            tv_sec: remain.as_secs() as _,
            tv_nsec: remain.subsec_nanos() as _,
        };
        let rc = libc::syscall(
            libc::SYS_futex,
            word as *const AtomicU32,
            FUTEX_WAIT,
            expected,
            &ts,
        );
        if rc < 0
            && !matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR | libc::EAGAIN | libc::ETIMEDOUT)
            )
        {
            return Err(format!("futex: {}", errno_s()));
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (word, expected);
        std::thread::sleep(remain.min(Duration::from_millis(2)));
    }
    Ok(())
}
fn wake_word(word: &AtomicU32) {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    unsafe {
        libc::syscall(libc::SYS_futex, word as *const AtomicU32, FUTEX_WAKE, 1i32);
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = word;
    }
}

/// double-checked by size plus header magic, so the process's own ART jit-cache memfd is ruled out
unsafe fn looks_like_ring(fd: i32) -> bool {
    let mut st: libc::stat = std::mem::zeroed();
    if libc::fstat(fd, &mut st) != 0 || st.st_size as u64 != proto::RING_FDSIZE {
        return false;
    }
    let mut hdr = [0u8; 128];
    if libc::pread(fd, hdr.as_mut_ptr() as *mut libc::c_void, 128, 0) != 128 {
        return false;
    }
    rd64(&hdr, proto::H_MAGIC) == proto::RING_MAGIC
        && rd32(&hdr, proto::H_VERSION) == proto::PROTO_VER
}

// ---------------- actions ----------------
fn do_ping(ring: &mut Ring) -> Result<Outcome, String> {
    let r = ring.rpc(|c| wr32(c, proto::C_TYPE, proto::CMD_PING))?;
    check_status(&r)?;
    let s = String::from_utf8_lossy(&r.data[..r.len]).into_owned();
    // "ij2art-payload pid=123 uid=456"
    let mut fields = vec![("message".into(), Json::text(s.clone()))];
    for tok in s.split_whitespace() {
        if let Some(v) = tok.strip_prefix("pid=").and_then(|v| v.parse().ok()) {
            fields.push(("pid".into(), Json::Int(v)));
        }
        if let Some(v) = tok.strip_prefix("uid=").and_then(|v| v.parse().ok()) {
            fields.push(("uid".into(), Json::Int(v)));
        }
    }
    Ok(Outcome::new(format!("[+] pong: {}\n", s), Json::Obj(fields)))
}

fn do_mods(ring: &mut Ring) -> Result<Outcome, String> {
    let r = ring.rpc(|c| wr32(c, proto::C_TYPE, proto::CMD_MODS))?;
    check_status(&r)?;
    let n = r.len / proto::MODENT_SIZE;
    let mut human = format!("{:>4}  {:>14}  {}\n", "#", "base", "name");
    let mut modules = Vec::new();
    for i in 0..n {
        let off = i * proto::MODENT_SIZE;
        let base = u64::from_ne_bytes(r.data[off..off + 8].try_into().unwrap());
        let name_area = &r.data[off + 8..off + proto::MODENT_SIZE];
        let end = name_area
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_area.len());
        let name = String::from_utf8_lossy(&name_area[..end]).into_owned();
        human.push_str(&format!("{:>4}  {:>14x}  {}\n", i, base, name));
        modules.push(Json::Obj(vec![
            ("base".into(), Json::hex(base)),
            ("name".into(), Json::text(name)),
        ]));
    }
    let truncated = r.flags & 1 != 0;
    if truncated {
        human.push_str("[!] list truncated (response slot full)\n");
    }
    Ok(Outcome::new(
        human,
        Json::Obj(vec![
            ("records".into(), Json::Arr(modules)),
            ("truncated".into(), Json::Bool(truncated)),
        ]),
    ))
}

fn do_read(ring: &mut Ring, addr_s: &str, len_s: &str) -> Result<Outcome, String> {
    let addr = parse_hex64(addr_s)?;
    let len = parse_num(len_s)? as usize;
    if len == 0 || len > proto::RSP_DATA_MAX {
        return Err(format!(
            "len must be in 1..={} (chunk larger blocks)",
            proto::RSP_DATA_MAX
        ));
    }
    let r = ring.rpc(|c| {
        wr32(c, proto::C_TYPE, proto::CMD_READ);
        wr64(c, proto::C_ADDR, addr);
        wr64(c, proto::C_LEN, len as u64);
    })?;
    check_status(&r)?;
    let hex: String = r.data[..r.len]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Outcome::new(
        hexdump(addr, &r.data[..r.len]),
        Json::Obj(vec![
            ("addr".into(), Json::hex(addr)),
            ("len".into(), Json::UInt(r.len as u64)),
            ("hex".into(), Json::text(hex)),
        ]),
    ))
}

fn do_write(ring: &mut Ring, addr_s: &str, hex_tokens: &[String]) -> Result<Outcome, String> {
    let addr = parse_hex64(addr_s)?;
    let hex: String = hex_tokens.concat();
    let bytes = hex_bytes(&hex)?;
    if bytes.is_empty() || bytes.len() > proto::CMD_DATA_MAX {
        return Err(format!("data length must be in 1..={} bytes", proto::CMD_DATA_MAX));
    }
    let r = ring.rpc(|c| {
        wr32(c, proto::C_TYPE, proto::CMD_WRITE);
        wr64(c, proto::C_ADDR, addr);
        wr64(c, proto::C_LEN, bytes.len() as u64);
        c[proto::C_DATA..proto::C_DATA + bytes.len()].copy_from_slice(&bytes);
    })?;
    check_status(&r)?;
    Ok(Outcome::new(
        format!("[+] wrote {} bytes @ {:#x}\n", bytes.len(), addr),
        Json::Obj(vec![
            ("addr".into(), Json::hex(addr)),
            ("written".into(), Json::UInt(bytes.len() as u64)),
        ]),
    ))
}

fn do_call(ring: &mut Ring, pid: i32, pos: &[String], args: &[String]) -> Result<Outcome, String> {
    let lib = opt_value(args, "--in", "/libc.so");
    let tok = &pos[0];
    let fnaddr = if tok.starts_with("0x") {
        parse_hex64(tok)?
    } else {
        // symbol call: locate the library in the target process's maps; if the on-disk parse
        // (section headers / PHDR) fails, fall back to the remote PT_DYNAMIC
        let maps = crate::procfs::maps(pid).map_err(|e| e.to_string())?;
        let (path, base) =
            crate::procfs::lib_base(&maps, &lib).ok_or(format!("{} not found in the target process", lib))?;
        crate::elf::sym_vaddr(&path, tok)
            .map(|off| base + off)
            .or_else(|| crate::elf::MemElf::load(pid, base).and_then(|mut m| m.sym_addr(tok)))
            .ok_or(format!("{} has no symbol {}", lib, tok))?
    };
    let mut a: Vec<u64> = Vec::new();
    for t in &pos[1..] {
        a.push(parse_hex64(t).map_err(|_| format!("invalid argument {}", t))?);
    }
    if a.len() > 8 {
        return Err("at most 8 arguments (x0..x7)".into());
    }
    let shown = tok.clone();
    let r = ring.rpc(|c| {
        wr32(c, proto::C_TYPE, proto::CMD_CALL);
        wr64(c, proto::C_ADDR, fnaddr);
        wr32(c, proto::C_ARGSN, a.len() as u32);
        for (i, v) in a.iter().enumerate() {
            wr64(c, proto::C_ARGS + i * 8, *v);
        }
    })?;
    check_status(&r)?;
    Ok(Outcome::new(
        format!(
            "[+] {}({}) = {:#x} ({})\n",
            shown,
            a.len(),
            r.retval,
            r.retval as i64
        ),
        Json::Obj(vec![
            ("target".into(), Json::text(shown)),
            ("addr".into(), Json::hex(fnaddr)),
            ("argc".into(), Json::UInt(a.len() as u64)),
            ("retval".into(), Json::hex(r.retval)),
            ("retval_signed".into(), Json::Int(r.retval as i64)),
        ]),
    ))
}

fn do_shutdown(ring: &mut Ring) -> Result<Outcome, String> {
    let r = ring.rpc(|c| wr32(c, proto::C_TYPE, proto::CMD_SHUTDOWN))?;
    check_status(&r)?;
    Ok(Outcome::new(
        "[+] shutdown request acknowledged, worker is exiting; the payload code is cleared when the app restarts\n",
        Json::Obj(vec![("shutdown".into(), Json::Bool(true))]),
    ))
}

// ---------------- small helpers ----------------
pub(crate) fn check_status(r: &Response) -> Result<(), String> {
    if r.status < 0 {
        if r.status <= -10 && !r.data.is_empty() {
            return Err(format!(
                "payload status={}: {}",
                r.status,
                String::from_utf8_lossy(&r.data)
            ));
        }
        Err(match r.status {
            -1 => "payload: invalid command".into(),
            -2 => "payload: address unmapped/not writable".into(),
            -3 => "payload: length exceeds limit".into(),
            n => format!("payload: error {}", n),
        })
    } else {
        Ok(())
    }
}

fn errno_s() -> String {
    std::io::Error::last_os_error().to_string()
}

fn parse_hex64(s: &str) -> Result<u64, String> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(h, 16).map_err(|_| format!("invalid number {}", s))
}

fn parse_num(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        parse_hex64(s)
    } else {
        s.parse().map_err(|_| format!("invalid number {}", s))
    }
}

fn hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let clean: String = hex
        .chars()
        .filter(|c| !matches!(c, ' ' | ':' | ',' | '\n'))
        .collect();
    if clean.len() % 2 != 0 {
        return Err("hex length must be even".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| "contains a non-hex character".to_string())
        })
        .collect()
}

pub(crate) fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}
pub(crate) fn rd64(b: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(b[off..off + 8].try_into().unwrap())
}
pub(crate) fn wr32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}
pub(crate) fn wr64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

fn hexdump(addr: u64, data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!(
            "  {:12x}  {:<47}  {}\n",
            addr + (i * 16) as u64,
            hex.join(" "),
            ascii
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clean_args_strips_global_flags() {
        let args: Vec<String> = "ij2art ctl --pid 9 --json inline list --wait 3"
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let (clean, wait) = clean_args(&args).unwrap();
        assert_eq!(wait, 3);
        assert_eq!(
            clean,
            "ij2art ctl --pid 9 inline list"
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
        let bad: Vec<String> = "ij2art ctl --pid 9 --wait x ping"
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        assert!(clean_args(&bad).is_err());
        let missing: Vec<String> = "ij2art ctl --pid 9 --wait"
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        assert!(clean_args(&missing).is_err());
    }
    #[test]
    fn plan_routes_without_io() {
        let p = |s: &str| {
            plan(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        };
        assert!(matches!(
            p("ij2art ctl --pid 1 overview").unwrap(),
            Plan::Basic(_)
        ));
        assert!(matches!(
            p("ij2art ctl --pid 1 batch").unwrap(),
            Plan::Basic(_)
        ));
        assert!(matches!(
            p("ij2art ctl --pid 1 inline list").unwrap(),
            Plan::Inline(_)
        ));
        assert!(matches!(
            p("ij2art ctl --pid 1 probe list").unwrap(),
            Plan::Probe(_)
        ));
        assert!(matches!(
            p("ij2art ctl --pid 1 lib list").unwrap(),
            Plan::Lib(_)
        ));
        assert!(matches!(
            p("ij2art ctl --pid 1 dex list").unwrap(),
            Plan::Art(_)
        ));
        assert!(p("ij2art ctl --pid 1").is_err());
        assert!(p("ij2art ctl --pid 1 bogus").is_err());
        // a malformed subcommand fails already at the plan stage, before the ring is opened
        assert!(p("ij2art ctl --pid 1 inline query 0").is_err());
    }
    #[test]
    fn extracts_payload_codes_for_json_errors() {
        assert_eq!(payload_code("payload status=-44: nope"), Some(-44));
        assert_eq!(payload_code("payload: error -1"), None);
        assert_eq!(payload_code("plain local error"), None);
    }
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        path: std::path::PathBuf,
        _file: fs::File,
        map: *mut u8,
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ij2art-ring-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.set_len(proto::RING_FDSIZE).unwrap();
            let map = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    proto::RING_FDSIZE as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(map, libc::MAP_FAILED);
            let map = map.cast::<u8>();
            let h = unsafe { core::slice::from_raw_parts_mut(map, 128) };
            wr64(h, proto::H_MAGIC, proto::RING_MAGIC);
            wr32(h, proto::H_VERSION, proto::PROTO_VER);
            wr32(h, proto::H_PID, std::process::id());
            wr32(h, proto::H_FLAGS, proto::RMF_WORKER);
            Self {
                path,
                _file: file,
                map,
            }
        }
        fn connect(&self) -> Ring {
            let fd: OwnedFd = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)
                .unwrap()
                .into();
            Ring::from_fd(fd, std::process::id() as i32).unwrap()
        }
        fn word(&self, off: usize) -> &AtomicU32 {
            unsafe { &*(self.map.add(off) as *const AtomicU32) }
        }
        fn command(&self) -> Vec<u8> {
            unsafe { core::slice::from_raw_parts(self.map.add(proto::CMD_OFF), 0x1000).to_vec() }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.map.cast(), proto::RING_FDSIZE as usize);
            }
            fs::remove_file(&self.path).unwrap();
        }
    }
    // an independent consumer operating on the same shared mapping; it can produce a late
    // response or a response whose identity does not match
    fn responder(map: usize, count: u32, corrupt: bool) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || unsafe {
            let p = map as *mut u8;
            let cmd_seq = &*(p.add(proto::H_CMD_SEQ) as *const AtomicU32);
            let rsp_seq = &*(p.add(proto::H_RSP_SEQ) as *const AtomicU32);
            let mut last = rsp_seq.load(Ordering::Acquire);
            for n in 1..=count {
                let until = Instant::now() + Duration::from_secs(2);
                let seq = loop {
                    let v = cmd_seq.load(Ordering::Acquire);
                    if v != last {
                        break v;
                    }
                    assert!(Instant::now() < until, "no command received");
                    std::thread::sleep(Duration::from_millis(1));
                };
                let c = core::slice::from_raw_parts(p.add(proto::CMD_OFF), 0x1000).to_vec();
                let r = core::slice::from_raw_parts_mut(p.add(proto::RSP_OFF), 0x4000);
                r.fill(0);
                wr32(r, proto::R_TYPE, rd32(&c, proto::C_TYPE));
                wr32(r, proto::R_ID, rd32(&c, proto::C_ID));
                wr64(
                    r,
                    proto::R_SESSION,
                    rd64(&c, proto::C_SESS) + u64::from(corrupt),
                );
                wr64(r, proto::R_RETVAL, n as u64 * 0x111);
                last = seq;
                rsp_seq.store(seq, Ordering::Release);
                wake_word(rsp_seq);
            }
        })
    }
    #[test]
    fn timeout_reconnect_does_not_overwrite_or_accept_the_old_request() {
        let f = Fixture::new();
        let mut a = f.connect();
        let old_session = a.session;
        assert!(a
            .rpc_timeout(
                |c| wr32(c, proto::C_TYPE, proto::CMD_PING),
                Duration::from_millis(10)
            )
            .is_err());
        let pending = f.command();
        drop(a);
        let mut b = f.connect();
        assert_ne!(old_session, b.session);
        assert!(b
            .rpc_timeout(
                |c| wr32(c, proto::C_TYPE, proto::CMD_MODS),
                Duration::from_millis(10)
            )
            .is_err());
        assert_eq!(f.command(), pending, "the command slot must not be written while an old request is incomplete");
        let worker = responder(f.map as usize, 2, false);
        let rsp = b
            .rpc_timeout(
                |c| wr32(c, proto::C_TYPE, proto::CMD_PING),
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(rsp.retval, 0x222, "the response to the new command must be accepted");
        worker.join().unwrap();
    }
    #[test]
    fn response_with_wrong_session_is_rejected() {
        let f = Fixture::new();
        let mut c = f.connect();
        let worker = responder(f.map as usize, 1, true);
        assert!(c
            .rpc_timeout(
                |b| wr32(b, proto::C_TYPE, proto::CMD_PING),
                Duration::from_secs(1)
            )
            .unwrap_err()
            .contains("identity"));
        worker.join().unwrap();
    }
    #[test]
    fn sequence_wrap_does_not_confuse_a_completed_request() {
        let f = Fixture::new();
        f.word(proto::H_CMD_SEQ).store(u32::MAX, Ordering::Release);
        f.word(proto::H_RSP_SEQ).store(u32::MAX, Ordering::Release);
        let mut c = f.connect();
        let worker = responder(f.map as usize, 1, false);
        c.rpc_timeout(
            |b| wr32(b, proto::C_TYPE, proto::CMD_PING),
            Duration::from_secs(1),
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(f.word(proto::H_CMD_SEQ).load(Ordering::Acquire), 0);
    }
    #[test]
    fn another_cli_is_excluded_and_lock_is_released_on_close() {
        let f = Fixture::new();
        let c = f.connect();
        let child = |blocked: bool| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "ctl::tests::file_lock_child", "--nocapture"])
                .env("IJ2ART_TEST_RING_PATH", &f.path)
                .env("IJ2ART_TEST_RING_PID", std::process::id().to_string())
                .env(
                    "IJ2ART_TEST_LOCK_BLOCKED",
                    if blocked { "1" } else { "0" },
                )
                .output()
                .unwrap()
        };
        let busy = child(true);
        assert!(
            busy.status.success(),
            "{}",
            String::from_utf8_lossy(&busy.stderr)
        );
        drop(c);
        let available = child(false);
        assert!(
            available.status.success(),
            "{}",
            String::from_utf8_lossy(&available.stderr)
        );
    }
    #[test]
    fn file_lock_child() {
        let Some(path) = std::env::var_os("IJ2ART_TEST_RING_PATH") else {
            return;
        };
        let pid: i32 = std::env::var("IJ2ART_TEST_RING_PID")
            .unwrap()
            .parse()
            .unwrap();
        let fd: OwnedFd = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
            .into();
        let result = Ring::from_fd(fd, pid);
        if std::env::var("IJ2ART_TEST_LOCK_BLOCKED").unwrap() == "1" {
            assert!(result.err().unwrap().contains("busy"));
        } else {
            assert!(result.is_ok());
        }
    }
}
