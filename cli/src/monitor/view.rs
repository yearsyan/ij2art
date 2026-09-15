//! Event decoding plus user-space enrichment and rendering: nr names, sockaddr, pc -> library
//! attribution (a best-effort frame chain), and the fd table (tgid-level and shared by
//! threads). Whenever an attribution is uncertain it is labeled explicitly rather than guessed
//! (design decision D8).
use super::{EvSys, EVF_READ_FAIL, EVF_TRUNCATED, EV_SYS_ENTER, EV_SYS_EXIT, EVMAGIC};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NR_OPENAT: u32 = 56;
const NR_OPENAT2: u32 = 437;
const NR_EXECVE: u32 = 221;
const NR_EXECVEAT: u32 = 281;
const NR_READLINKAT: u32 = 78;
const NR_CONNECT: u32 = 203;
const NR_SENDTO: u32 = 206;
const NR_MINCORE: u32 = 232;
const NR_PTRACE: u32 = 117;
const NR_MMAP: u32 = 222;
const NR_MPROTECT: u32 = 226;
const NR_MEMFD: u32 = 279;
const NR_CLOSE: u32 = 57;
const NR_DUP: u32 = 23;
const NR_DUP3: u32 = 24;
const NR_CLOSE_RANGE: u32 = 436;

pub fn sysname(nr: u32) -> &'static str {
    match nr {
        17 => "getcwd", 21 => "ioctl", 23 => "dup", 24 => "dup3", 29 => "shmget",
        40 => "mount", 41 => "umount2", 48 => "faccessat", 49 => "chdir",
        56 => "openat", 57 => "close", 58 => "vhangup",
        59 => "pipe2", 61 => "getdents64", 62 => "lseek", 63 => "read",
        64 => "write", 66 => "writev", 78 => "readlinkat", 79 => "newfstatat",
        93 => "exit", 96 => "set_tid_address", 98 => "futex",
        99 => "set_robust_list", 117 => "ptrace", 124 => "sched_setaffinity",
        129 => "kill", 131 => "tgkill", 134 => "rt_sigaction",
        135 => "rt_sigprocmask", 143 => "setregid", 144 => "setgid",
        145 => "setreuid", 146 => "setuid", 147 => "setresuid",
        149 => "setresgid", 159 => "setgroups", 160 => "uname",
        167 => "prctl", 172 => "getpid", 173 => "getppid",
        174 => "getuid", 176 => "gettid", 178 => "sysinfo",
        198 => "socket", 199 => "socketpair", 200 => "bind", 201 => "listen",
        202 => "accept", 203 => "connect", 204 => "getsockname",
        205 => "getpeername", 206 => "sendto", 207 => "recvfrom",
        208 => "setsockopt", 209 => "getsockopt", 210 => "shutdown",
        211 => "sendmsg", 212 => "recvmsg", 213 => "readv",
        214 => "brk", 215 => "munmap", 216 => "mremap",
        217 => "add_key", 218 => "request_key", 219 => "keyctl",
        220 => "clone", 221 => "execve", 222 => "mmap",
        223 => "fadvise64", 224 => "swapon", 225 => "swapoff", 226 => "mprotect",
        227 => "msync", 232 => "mincore", 233 => "madvise",
        260 => "wait4", 262 => "newstat", 263 => "newfstat",
        267 => "readahead", 270 => "process_vm_readv", 271 => "process_vm_writev",
        279 => "memfd_create", 281 => "execveat",
        285 => "newuname", 291 => "epoll_ctl", 292 => "epoll_pwait",
        425 => "io_uring_setup", 427 => "statx", 434 => "pidfd_open",
        435 => "clone3", 436 => "close_range", 437 => "openat2",
        438 => "pidfd_getfd", 439 => "faccessat2",
        _ => "?",
    }
}

pub fn proc_comm(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim_end_matches('\n')
        .to_string()
}

// ---------------- decode ----------------

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Decode field by field instead of casting pointers with unsafe, which sidesteps any
/// alignment disputes. The layout is defined in bpf/monitor.h.
pub fn decode(rec: &[u8]) -> Result<EvSys, String> {
    if rec.len() != 240 {
        return Err(format!("event length error: expected=240 actual={}", rec.len()));
    }
    let hdr = super::EvHdr {
        magic: rd32(rec, 0),
        kind: rd16(rec, 4),
        len: rd16(rec, 6),
        cpu: rd32(rec, 8),
        pid: rd32(rec, 12),
        tid: rd32(rec, 16),
        status: rd32(rec, 20),
        ts_ns: rd64(rec, 24),
        pc: rd64(rec, 32),
        aux: rd64(rec, 40),
    };
    if hdr.magic != EVMAGIC {
        return Err(format!("event magic error: expected={EVMAGIC:#x} actual={:#x}", hdr.magic));
    }
    if hdr.kind != EV_SYS_ENTER && hdr.kind != EV_SYS_EXIT {
        return Err(format!("unsupported event kind={}", hdr.kind));
    }
    if hdr.len as usize != rec.len() {
        return Err(format!("event header length inconsistent with payload: hdr.len={} actual={}", hdr.len, rec.len()));
    }
    let mut args = [0u64; 6];
    for i in 0..6 {
        args[i] = rd64(rec, 48 + i * 8);
    }
    let ret = rd64(rec, 96) as i64;
    let mut fp = [0u64; 4];
    for i in 0..4 {
        fp[i] = rd64(rec, 104 + i * 8);
    }
    let data_len = rd16(rec, 136) as usize;
    let mut data = [0u8; 96];
    if data_len > data.len() {
        return Err(format!("event data_len out of range: {data_len} > {}", data.len()));
    }
    let n = data_len;
    data[..n].copy_from_slice(&rec[138..138 + n]);
    Ok(EvSys {
        hdr,
        args,
        ret,
        fp,
        data_len: n as u16,
        data,
        pad: [0; 6],
    })
}

// ---------------- enrichment ----------------

struct Pend {
    args: [u64; 6],
    path: Option<String>,
    at: Instant,
}

pub struct Renderer {
    json: bool,
    wall_base: SystemTime,
    mono_base: u64,
    maps_cache: HashMap<u32, (Instant, Vec<crate::procfs::MapEnt>)>,
    fdtab: HashMap<(u32, u32), String>,
    pending: HashMap<(u32, u32), Pend>,
    /// Line buffer: the main loop flushes stdout once per poll cycle (a println per line is a
    /// bottleneck under a flood)
    out: String,
}

impl Renderer {
    pub fn new(json: bool) -> Renderer {
        Renderer {
            json,
            wall_base: SystemTime::now(),
            mono_base: now_monotonic_ns(),
            maps_cache: HashMap::new(),
            fdtab: HashMap::new(),
            pending: HashMap::new(),
            out: String::new(),
        }
    }

    /// Take the lines waiting to be flushed and clear the buffer.
    pub fn take_output(&mut self) -> String {
        std::mem::take(&mut self.out)
    }

    pub fn render(&mut self, rec: &[u8]) -> Result<(), String> {
        let ev = decode(rec)?;
        // fd table upkeep: an enter records the pending call and the matching exit settles it;
        // a 2-second freshness check filters out tid reuse
        match ev.hdr.kind {
            EV_SYS_ENTER => self.on_enter(&ev),
            EV_SYS_EXIT => self.on_exit(&ev),
            _ => {}
        }
        if self.json {
            self.render_json(&ev);
        } else {
            self.render_text(&ev);
        }
        Ok(())
    }

    fn on_enter(&mut self, ev: &EvSys) {
        let nr = ev.hdr.aux as u32;
        let path = if matches!(nr, NR_OPENAT | NR_OPENAT2 | NR_EXECVE | NR_EXECVEAT | NR_READLINKAT | NR_MEMFD)
            && ev.data_len > 0
        {
            Some(cstr_of(&ev.data))
        } else {
            None
        };
        self.pending.insert(
            (ev.hdr.tid, nr),
            Pend {
                args: ev.args,
                path,
                at: Instant::now(),
            },
        );
    }

    fn on_exit(&mut self, ev: &EvSys) {
        let nr = ev.hdr.aux as u32;
        let Some(p) = self.pending.get(&(ev.hdr.tid, nr)) else {
            return;
        };
        if p.at.elapsed() > Duration::from_secs(2) || ev.ret < 0 {
            return; // a stale pairing or a failed call is not settled
        }
        let fd = ev.ret as u32;
        let pid = ev.hdr.pid;
        match nr {
            NR_OPENAT | NR_OPENAT2 => {
                self.fdtab
                    .insert((pid, fd), p.path.clone().unwrap_or_else(|| "?".into()));
            }
            NR_DUP => {
                if let Some(src) = self.fdtab.get(&(pid, p.args[0] as u32)).cloned() {
                    self.fdtab.insert((pid, fd), src);
                }
            }
            NR_DUP3 => {
                if let Some(src) = self.fdtab.get(&(pid, p.args[0] as u32)).cloned() {
                    self.fdtab.insert((pid, fd), src);
                }
            }
            NR_CLOSE => {
                self.fdtab.remove(&(pid, p.args[0] as u32));
            }
            NR_CLOSE_RANGE => {
                let (first, last) = (p.args[0] as u32, p.args[1] as u32);
                if last >= first && last - first < 1024 {
                    for f in first..=last {
                        self.fdtab.remove(&(pid, f));
                    }
                }
            }
            _ => {}
        }
    }

    fn fmt_ts(&self, ts_ns: u64) -> String {
        let delta = ts_ns.saturating_sub(self.mono_base);
        let wall = self.wall_base + Duration::from_nanos(delta);
        let since = wall.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = since.as_secs() % 86_400;
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            secs / 3600,
            (secs % 3600) / 60,
            secs % 60,
            since.subsec_millis()
        )
    }

    fn maps_of(&mut self, pid: u32) -> &[crate::procfs::MapEnt] {
        let stale = match self.maps_cache.get(&pid) {
            Some((at, _)) => at.elapsed() > Duration::from_secs(2),
            None => true,
        };
        if stale {
            if let Ok(m) = crate::procfs::maps(pid as i32) {
                self.maps_cache.insert(pid, (Instant::now(), m));
            } else if !self.maps_cache.contains_key(&pid) {
                self.maps_cache.insert(pid, (Instant::now(), Vec::new()));
            }
        }
        self.maps_cache
            .get(&pid)
            .map(|(_, m)| m.as_slice())
            .unwrap_or(&[])
    }

    /// pc -> "libname+0xoff"; an anonymous executable mapping -> "anon_exec+0xoff"; a miss -> "?"
    fn lib_of(&mut self, pid: u32, pc: u64) -> String {
        if pc == 0 {
            return String::new();
        }
        let maps = self.maps_of(pid);
        if let Some(m) = maps
            .iter()
            .find(|m| pc >= m.start && pc < m.end && m.flags.contains('x'))
        {
            let name = m
                .path
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .unwrap_or(if m.path.is_empty() { "anon_exec" } else { "?" });
            return format!("{}+0x{:x}", name, pc - m.start);
        }
        "?".into()
    }

    /// The caller is the first frame in the frame chain that lies outside libc/vDSO; if every
    /// frame is inside libc, or the chain is missing, the result is None.
    fn caller_of(&mut self, pid: u32, ev: &EvSys) -> Option<String> {
        for &lr in &ev.fp {
            if lr == 0 {
                return None;
            }
            let lib = self.lib_of(pid, lr);
            if lib.is_empty() || lib == "?" {
                continue;
            }
            let base = lib.split('+').next().unwrap_or("");
            if base == "libc.so" || base == "vdso" || base.contains("vdso") {
                continue;
            }
            return Some(lib);
        }
        None
    }

    fn render_text(&mut self, ev: &EvSys) {
        let nr = ev.hdr.aux as u32;
        let name = sysname(nr);
        let pid = ev.hdr.pid;
        let ts = self.fmt_ts(ev.hdr.ts_ns);
        let mut flags = String::new();
        if ev.hdr.status & EVF_TRUNCATED != 0 {
            flags.push_str(" [truncated]");
        }
        if ev.hdr.status & EVF_READ_FAIL != 0 {
            flags.push_str(" [read failed]");
        }
        match ev.hdr.kind {
            EV_SYS_ENTER => {
                let detail = self.enter_detail(nr, ev);
                let pc = self.lib_of(pid, ev.hdr.pc);
                let caller = self.caller_of(pid, ev);
                let _ = writeln!(
                    self.out,
                    "[sys] {ts} pid={pid} tid={} {name}({detail}) pc={pc}{}",
                    ev.hdr.tid,
                    caller.map(|c| format!(" caller={c}")).unwrap_or_default(),
                );
            }
            EV_SYS_EXIT => {
                let extra = self.exit_extra(nr, pid, ev);
                let _ = writeln!(
                    self.out,
                    "[sys] {ts} pid={pid} tid={} {name} -> {}({})",
                    ev.hdr.tid,
                    ev.ret,
                    extra
                );
            }
            _ => {}
        }
        if !flags.is_empty() {
            let _ = writeln!(self.out, "       {flags}");
        }
    }

    fn enter_detail(&mut self, nr: u32, ev: &EvSys) -> String {
        let a = ev.args;
        match nr {
            NR_OPENAT | NR_OPENAT2 => format!("\"{}\" flags={:#x}", cstr_of(&ev.data), a[2]),
            NR_EXECVE | NR_EXECVEAT | NR_READLINKAT | NR_MEMFD => {
                format!("\"{}\"", cstr_of(&ev.data))
            }
            NR_CONNECT | NR_SENDTO => sockaddr_str(&ev.data),
            NR_MINCORE => format!("{:#x} len={:#x}", a[0], a[1]),
            NR_PTRACE => format!("req={:#x} pid={}", a[0], a[1]),
            NR_MMAP => format!(
                "len={:#x} prot={} flags={:#x}",
                a[1],
                prot_str(a[2] as u32),
                a[3]
            ),
            NR_MPROTECT => format!("{:#x} len={:#x} prot={}", a[0], a[1], prot_str(a[2] as u32)),
            NR_CLOSE | NR_DUP => format!("fd={}", a[0]),
            NR_DUP3 => format!("old={} new={}", a[0], a[1]),
            NR_CLOSE_RANGE => format!("{}..{}", a[0], a[1]),
            _ => format!("a0={:#x} a1={:#x} a2={:#x}", a[0], a[1], a[2]),
        }
    }

    fn exit_extra(&mut self, nr: u32, pid: u32, ev: &EvSys) -> String {
        let fd = if ev.ret >= 0 { ev.ret as u32 } else { return String::new() };
        match nr {
            NR_OPENAT | NR_OPENAT2 | NR_DUP | NR_DUP3 => self
                .fdtab
                .get(&(pid, fd))
                .map(|p| format!("\"{p}\""))
                .unwrap_or_else(|| "?".into()),
            _ => String::new(),
        }
    }

    fn render_json(&mut self, ev: &EvSys) {
        let nr = ev.hdr.aux as u32;
        let pid = ev.hdr.pid;
        let kind = if ev.hdr.kind == EV_SYS_ENTER { "sys_enter" } else { "sys_exit" };
        let ts = self.fmt_ts(ev.hdr.ts_ns);
        let detail = match ev.hdr.kind {
            EV_SYS_ENTER => {
                let pc = self.lib_of(pid, ev.hdr.pc);
                let caller = self.caller_of(pid, ev);
                format!(
                    "\"args\":[{},{},{},{},{},{}],\"pc\":\"{}\",\"caller\":{}",
                    ev.args[0],
                    ev.args[1],
                    ev.args[2],
                    ev.args[3],
                    ev.args[4],
                    ev.args[5],
                    pc,
                    match caller {
                        Some(c) => format!("\"{c}\""),
                        None => "null".into(),
                    }
                )
            }
            _ => format!("\"ret\":{}", ev.ret),
        };
        let data = json_escape(&cstr_of(&ev.data));
        let _ = writeln!(
            self.out,
            "{{\"ts\":\"{ts}\",\"kind\":\"{kind}\",\"pid\":{pid},\"tid\":{},\"cpu\":{},\"nr\":{nr},\"name\":\"{}\",{detail},\"data\":\"{data}\",\"trunc\":{},\"rd_fail\":{}}}",
            ev.hdr.tid,
            ev.hdr.cpu,
            sysname(nr),
            (ev.hdr.status & EVF_TRUNCATED != 0) as u8,
            (ev.hdr.status & EVF_READ_FAIL != 0) as u8,
        );
    }
}

fn now_monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn cstr_of(data: &[u8]) -> String {
    let end = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn prot_str(p: u32) -> String {
    // mmap/mprotect prot bits: 0x1 is R, 0x2 is W, and 0x4 is X; any remaining bits are
    // appended in hex
    let mut s = String::new();
    if p & 1 != 0 {
        s.push('R');
    }
    if p & 2 != 0 {
        s.push('W');
    }
    if p & 4 != 0 {
        s.push('X');
    }
    if p & !7 != 0 {
        s.push_str(&format!("|{:#x}", p & !7));
    }
    if s.is_empty() {
        s.push_str("NONE");
    }
    s
}

/// Raw sockaddr bytes (fetched at a fixed length per family; see bpf/sys.c) -> a readable
/// string.
pub fn sockaddr_str(data: &[u8]) -> String {
    if data.len() < 4 {
        return "<none>".into();
    }
    let fam = u16::from_le_bytes([data[0], data[1]]);
    match fam {
        2 => {
            // AF_INET: the port is big-endian at offset 2 and the address sits at offset 4
            if data.len() >= 8 {
                let port = u16::from_be_bytes([data[2], data[3]]);
                format!("AF_INET {}.{}.{}.{}:{}", data[4], data[5], data[6], data[7], port)
            } else {
                "AF_INET <truncated>".into()
            }
        }
        10 => {
            if data.len() >= 26 {
                let port = u16::from_be_bytes([data[2], data[3]]);
                let mut ip = String::new();
                for seg in data[8..24].chunks(2) {
                    if !ip.is_empty() {
                        ip.push(':');
                    }
                    ip.push_str(&format!("{:x}", u16::from_be_bytes([seg[0], seg[1]])));
                }
                format!("AF_INET6 [{ip}]:{port}")
            } else {
                "AF_INET6 <truncated>".into()
            }
        }
        1 => {
            let path = cstr_of(&data[2..]);
            format!("AF_UNIX \"{path}\"")
        }
        16 => "AF_NETLINK".into(),
        _ => format!("AF_{fam}"),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_synthetic_enter_event() {
        let mut rec = [0u8; 240];
        rec[0..4].copy_from_slice(&EVMAGIC.to_le_bytes());
        rec[4..6].copy_from_slice(&EV_SYS_ENTER.to_le_bytes());
        rec[6..8].copy_from_slice(&240u16.to_le_bytes());
        rec[12..16].copy_from_slice(&4321u32.to_le_bytes()); // pid
        rec[16..20].copy_from_slice(&4321u32.to_le_bytes()); // tid
        rec[40..48].copy_from_slice(&56u64.to_le_bytes()); // aux = openat
        rec[48..56].copy_from_slice(&0xffffffffffffff9cu64.to_le_bytes()); // dirfd AT_FDCWD
        rec[136..138].copy_from_slice(&10u16.to_le_bytes()); // data_len
        rec[138..148].copy_from_slice(b"/data/x\0\0\0");
        let ev = decode(&rec).unwrap();
        assert_eq!(ev.hdr.pid, 4321);
        assert_eq!(ev.hdr.aux, 56);
        assert_eq!(cstr_of(&ev.data), "/data/x");
        assert_eq!(sysname(56), "openat");
    }

    #[test]
    fn malformed_events_fail_with_diagnostics() {
        let mut rec = [0u8; 240];
        rec[..4].copy_from_slice(&EVMAGIC.to_le_bytes());
        rec[4..6].copy_from_slice(&EV_SYS_ENTER.to_le_bytes());
        rec[6..8].copy_from_slice(&240u16.to_le_bytes());
        assert!(decode(&rec[..239]).err().unwrap().contains("length"));
        let mut bad = rec;
        bad[0] ^= 1;
        assert!(decode(&bad).err().unwrap().contains("magic"));
        bad = rec;
        bad[4..6].copy_from_slice(&99u16.to_le_bytes());
        assert!(decode(&bad).err().unwrap().contains("kind"));
        bad = rec;
        bad[6..8].copy_from_slice(&239u16.to_le_bytes());
        assert!(decode(&bad).err().unwrap().contains("hdr.len"));
        bad = rec;
        bad[136..138].copy_from_slice(&97u16.to_le_bytes());
        assert!(decode(&bad).err().unwrap().contains("data_len"));
        let mut renderer = Renderer::new(false);
        assert!(renderer.render(&bad).is_err());
        assert!(renderer.take_output().is_empty());
    }

    #[test]
    fn sockaddr_variants() {
        let mut v4 = vec![2u8, 0, 0x01, 0xbb, 1, 2, 3, 4];
        v4.resize(16, 0);
        assert_eq!(sockaddr_str(&v4), "AF_INET 1.2.3.4:443");
        let mut v6 = vec![10u8, 0, 0x01, 0xbb];
        v6.extend_from_slice(&[0u8; 4]); // flowinfo
        v6.extend_from_slice(&[
            0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        v6.extend_from_slice(&[0u8; 4]);
        assert_eq!(sockaddr_str(&v6), "AF_INET6 [2001:0:0:0:0:0:0:1]:443");
        let ux = [1u8, 0].iter().copied().chain(b"/dev/socket/x\0".iter().copied()).collect::<Vec<u8>>();
        assert_eq!(sockaddr_str(&ux), "AF_UNIX \"/dev/socket/x\"");
    }

    #[test]
    fn prot_render() {
        assert_eq!(prot_str(5), "RX");
        assert_eq!(prot_str(3), "RW");
        assert_eq!(prot_str(0), "NONE");
    }
}
