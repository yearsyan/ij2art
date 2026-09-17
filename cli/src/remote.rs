// Remote calls through ptrace with a bounded wait: the full context is restored only when
// the call returns normally.
// An unknown execution state cannot be undone by restoring the PC, so the stop site has to
// be kept and any further remote operation has to be refused.
use crate::procfs;
use std::cell::Cell;
use std::time::{Duration, Instant};

const PTRACE_SEIZE: i64 = 0x4206;
const PTRACE_INTERRUPT: i64 = 0x4207;
const PTRACE_CONT: i64 = 7;
const PTRACE_DETACH: i64 = 17;
const PTRACE_GETREGSET: i64 = 0x4204;
const PTRACE_SETREGSET: i64 = 0x4205;
const PTRACE_GETSIGMASK: i64 = 0x420a;
const PTRACE_SETSIGMASK: i64 = 0x420b;
const NT_PRSTATUS: u64 = 1;
const NT_PRFPREG: u64 = 2;
const NT_ARM_SVE: u64 = 0x405;
const NT_ARM_SSVE: u64 = 0x40b;
const NT_ARM_ZA: u64 = 0x40c;
const NT_ARM_ZT: u64 = 0x40d;
const WALL: i32 = 0x4000_0000;
// A canonical, untagged, deliberately unaligned instruction address. A return
// through a tagged value can sign-extend bit 55 (observed on Pixel 7 / Android
// 17), changing the fault PC and making a normal return look like a crash.
// Keep exact PC matching below: stripping tags there could hide a real fault.
pub const RET_SENTINEL: u64 = 1;

/// AArch64 android_dlextinfo wire layout from <android/dlext.h>. Passing an
/// existing fd avoids reopening /proc/self/fd, which zygote SELinux can deny.
pub fn library_fd_extinfo(fd: i32) -> [u8; 48] {
    let mut info = [0; 48];
    info[..8].copy_from_slice(&0x10u64.to_le_bytes()); // ANDROID_DLEXT_USE_LIBRARY_FD
    info[28..32].copy_from_slice(&fd.to_le_bytes());
    info
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct Regs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

fn ptrace(req: i64, tid: i32, addr: u64, data: u64) -> i64 {
    #[cfg(test)]
    if let Some(ret) = tests::mock_ptrace(req, tid, addr, data) {
        return ret;
    }
    #[cfg(any(target_os = "android", target_os = "linux"))]
    return unsafe { libc::syscall(libc::SYS_ptrace, req, tid, addr, data) };
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = (req, tid, addr, data);
        -1
    }
}
fn waitpid(tid: i32, status: &mut i32, options: i32) -> i32 {
    #[cfg(test)]
    if let Some(ret) = tests::mock_waitpid(tid, status) {
        return ret;
    }
    unsafe { libc::waitpid(tid, status, options) }
}

fn wait_status_until(tid: i32, deadline: Instant) -> Result<i32, String> {
    loop {
        let mut st = 0;
        let ret = waitpid(tid, &mut st, WALL | libc::WNOHANG);
        if ret > 0 {
            return Ok(st);
        }
        if ret < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(format!(
                "waitpid {}: {}",
                tid,
                std::io::Error::last_os_error()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!("waiting for tid {} timed out", tid));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn stopped_until(tid: i32, deadline: Instant) -> Result<(), String> {
    loop {
        let st = wait_status_until(tid, deadline)?;
        if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
            return Err(format!("tid {} exited", tid));
        }
        if libc::WIFSTOPPED(st) {
            return Ok(());
        }
    }
}

struct Context {
    regs: Regs,
    // The vector state cannot rely on the caller-saved convention of the ordinary function
    // call ABI.
    extensions: Vec<(u64, Vec<u8>)>,
    sigmask: u64,
}

pub struct Remote {
    pub pid: i32,
    pub tids: Vec<i32>, // records only the threads that have already been SEIZE'd successfully
    stopped: std::collections::HashSet<i32>,
    deadline: Cell<Instant>,
    unsafe_state: Cell<bool>,
    main_running: Cell<bool>,
}

impl Remote {
    pub fn new(pid: i32) -> Self {
        Self {
            pid,
            tids: Vec::new(),
            stopped: Default::default(),
            deadline: Cell::new(Instant::now() + Duration::from_secs(25)),
            unsafe_state: Cell::new(false),
            main_running: Cell::new(false),
        }
    }
    pub fn reset_timeout(&self, duration: Duration) {
        self.deadline.set(Instant::now() + duration);
    }
    pub fn usable(&self) -> bool {
        !self.unsafe_state.get()
    }
    pub fn mark_unsafe(&self) {
        self.unsafe_state.set(true);
    }

    pub fn seize_all(&mut self) -> Result<(), String> {
        if !self.tids.is_empty() {
            return Err("thread group is already owned by this object".into());
        }
        let status = std::fs::read_to_string(format!("/proc/{}/status", self.pid))
            .map_err(|e| e.to_string())?;
        if status
            .lines()
            .filter_map(|l| l.strip_prefix("State:"))
            .any(|s| s.trim_start().starts_with(['T', 't']))
        {
            return Err("target is already stopped; refusing to overwrite a remote execution state that may still need restoring".into());
        }
        // Stop the main thread first, so that fork is blocked, and then enumerate the
        // remaining threads round by round until the set becomes stable.
        let mut pending = vec![self.pid];
        loop {
            for tid in pending {
                if self.tids.contains(&tid) {
                    continue;
                }
                if ptrace(PTRACE_SEIZE, tid, 0, 0) != 0 {
                    if tid != self.pid
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                    {
                        continue;
                    }
                    return Err(format!(
                        "seize tid {}: {}",
                        tid,
                        std::io::Error::last_os_error()
                    ));
                }
                self.tids.push(tid);
                if ptrace(PTRACE_INTERRUPT, tid, 0, 0) != 0 {
                    return Err(format!(
                        "interrupt tid {}: {}",
                        tid,
                        std::io::Error::last_os_error()
                    ));
                }
                stopped_until(tid, self.deadline.get())?;
                self.stopped.insert(tid);
            }
            pending = std::fs::read_dir(format!("/proc/{}/task", self.pid))
                .map_err(|e| format!("re-enumerate threads: {}", e))?
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
                .filter(|tid| !self.tids.contains(tid))
                .collect();
            if pending.is_empty() {
                return Ok(());
            }
            if Instant::now() >= self.deadline.get() {
                return Err("timed out waiting for the thread group to stabilize".into());
            }
        }
    }

    pub fn detach_all(&mut self) -> Result<(), String> {
        if self.tids.is_empty() {
            return Ok(());
        }
        let mut errors = Vec::new();
        if !self.usable() {
            // Queue a process-level STOP first and only then DETACH, so that the tracer
            // exiting cannot let a polluted PC keep running.
            #[cfg(not(test))]
            if unsafe { libc::kill(self.pid, libc::SIGSTOP) } != 0 {
                errors.push(format!(
                    "pid {} SIGSTOP: {}",
                    self.pid,
                    std::io::Error::last_os_error()
                ));
            }
            eprintln!("[!] pid {} remote execution state unknown; keeping the SIGSTOP stopped state; inspect/restart the process, do not SIGCONT or retry automatically", self.pid);
        }
        let tids = self.tids.clone();
        for tid in tids.into_iter().rev() {
            if !self.stopped.contains(&tid) || (tid == self.pid && self.main_running.get()) {
                let _ = ptrace(PTRACE_INTERRUPT, tid, 0, 0);
                if let Err(e) = stopped_until(tid, Instant::now() + Duration::from_secs(2)) {
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                        errors.push(e);
                    }
                }
            }
            let signal = if self.usable() {
                0
            } else {
                libc::SIGSTOP as u64
            };
            if ptrace(PTRACE_DETACH, tid, 0, signal) == 0
                || (std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                    && !std::path::Path::new(&format!("/proc/{}/task/{}", self.pid, tid)).exists())
            {
                self.tids.retain(|&t| t != tid);
                self.stopped.remove(&tid);
            } else {
                errors.push(format!(
                    "detach tid {}: {}",
                    tid,
                    std::io::Error::last_os_error()
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
    pub fn finish<T>(&mut self, result: Result<T, String>) -> Result<T, String> {
        match (result, self.detach_all()) {
            (Ok(v), Ok(())) => Ok(v),
            (Err(e), Ok(())) => Err(e),
            (Ok(_), Err(e)) => Err(e),
            (Err(a), Err(b)) => Err(format!("{}; {}", a, b)),
        }
    }

    fn regset(&self, kind: u64, size: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut bytes = vec![0u8; size];
        let mut io = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: size,
        };
        if ptrace(PTRACE_GETREGSET, self.pid, kind, &mut io as *mut _ as u64) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if io.iov_len > size {
            return Err(std::io::Error::other("regset exceeds buffer"));
        }
        bytes.truncate(io.iov_len);
        Ok(bytes)
    }
    fn put_regset(&self, kind: u64, bytes: &[u8]) -> Result<(), String> {
        let io = libc::iovec {
            iov_base: bytes.as_ptr() as *mut _,
            iov_len: bytes.len(),
        };
        if ptrace(PTRACE_SETREGSET, self.pid, kind, &io as *const _ as u64) != 0 {
            return Err(format!(
                "restore regset {:#x}: {}",
                kind,
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    fn getregs(&self) -> Result<Regs, String> {
        let bytes = self
            .regset(NT_PRSTATUS, core::mem::size_of::<Regs>())
            .map_err(|e| e.to_string())?;
        if bytes.len() != core::mem::size_of::<Regs>() {
            return Err("unsupported general register layout (AArch64 required)".into());
        }
        Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast()) })
    }
    fn setregs(&self, regs: &Regs) -> Result<(), String> {
        let bytes = unsafe {
            core::slice::from_raw_parts(regs as *const _ as *const u8, core::mem::size_of::<Regs>())
        };
        self.put_regset(NT_PRSTATUS, bytes)
    }
    fn capture(&self) -> Result<Context, String> {
        let regs = self.getregs()?;
        let fp = self
            .regset(NT_PRFPREG, 528)
            .map_err(|e| format!("save FP/SIMD: {}", e))?;
        if fp.len() != 528 {
            return Err("FP/SIMD regset is incomplete".into());
        }
        let mut extensions = vec![(NT_PRFPREG, fp)];
        for kind in [NT_ARM_SVE, NT_ARM_SSVE, NT_ARM_ZA, NT_ARM_ZT] {
            // Restoring SME/streaming SVE involves a mode switch, so an already enabled
            // state is rejected up front rather than claiming general support for it.
            let head = match self.regset(kind, if kind == NT_ARM_ZT { 64 } else { 16 }) {
                Ok(v) => v,
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(libc::EINVAL | libc::ENODEV | libc::EIO)
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(format!("read extension regset {:#x}: {}", kind, e)),
            };
            if kind != NT_ARM_SVE {
                return Err("kernel provides SME/streaming SVE state; this version refuses such remote calls".into());
            }
            if head.len() < 16 {
                return Err("SVE header is incomplete".into());
            }
            let len = u32::from_ne_bytes(head[..4].try_into().unwrap()) as usize;
            if !(16..=256 * 1024).contains(&len) {
                return Err("SVE length is invalid".into());
            }
            let data = self.regset(kind, len).map_err(|e| e.to_string())?;
            if data.len() != len {
                return Err("SVE regset is incomplete".into());
            }
            extensions.push((kind, data));
        }
        let mut sigmask = 0u64;
        if ptrace(
            PTRACE_GETSIGMASK,
            self.pid,
            8,
            &mut sigmask as *mut _ as u64,
        ) != 0
        {
            return Err(format!("save signal mask: {}", std::io::Error::last_os_error()));
        }
        Ok(Context {
            regs,
            extensions,
            sigmask,
        })
    }
    fn set_sigmask(&self, mask: u64) -> Result<(), String> {
        if ptrace(PTRACE_SETSIGMASK, self.pid, 8, &mask as *const _ as u64) != 0 {
            return Err(format!("set signal mask: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
    fn restore(&self, saved: &Context) -> Result<(), String> {
        let mut errors = Vec::new();
        for (kind, bytes) in &saved.extensions {
            if let Err(e) = self.put_regset(*kind, bytes) {
                errors.push(e);
            }
        }
        if let Err(e) = self.setregs(&saved.regs) {
            errors.push(e);
        }
        if let Err(e) = self.set_sigmask(saved.sigmask) {
            errors.push(e);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            self.mark_unsafe();
            Err(errors.join("; "))
        }
    }

    pub fn call(&self, func: u64, args: &[u64]) -> Result<u64, String> {
        if !self.usable() {
            return Err("previous remote call state unknown; refusing to continue".into());
        }
        if Instant::now() >= self.deadline.get() {
            return Err("timed out before execution; remote context not modified".into());
        }
        if !self.stopped.contains(&self.pid) || func == 0 || args.len() > 8 {
            return Err("remote call preconditions not satisfied".into());
        }
        let saved = self.capture()?;
        let mut regs = saved.regs;
        regs.sp = saved.regs.sp.checked_sub(2048).ok_or("stack address underflow")? & !15;
        regs.pc = func;
        regs.regs[30] = RET_SENTINEL;
        for (i, &a) in args.iter().enumerate() {
            regs.regs[i] = a;
        }
        // Keep asynchronous signals pending so that ART is not re-entered in the middle of
        // the call; synchronous exceptions are still received through ptrace.
        let mut mask = u64::MAX;
        for sig in [
            libc::SIGKILL,
            libc::SIGSTOP,
            libc::SIGSEGV,
            libc::SIGILL,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGSYS,
            libc::SIGTRAP,
            libc::SIGABRT,
        ] {
            mask &= !(1u64 << (sig - 1));
        }
        if let Err(e) = self.set_sigmask(mask).and_then(|_| self.setregs(&regs)) {
            return self.restore(&saved).and(Err(e));
        }
        if ptrace(PTRACE_CONT, self.pid, 0, 0) != 0 {
            let e = format!("cont: {}", std::io::Error::last_os_error());
            return self.restore(&saved).and(Err(e));
        }
        self.main_running.set(true);
        let outcome = wait_status_until(self.pid, self.deadline.get());
        match outcome {
            Ok(st) if libc::WIFSTOPPED(st) => {
                self.main_running.set(false);
                match self.getregs() {
                    Ok(out)
                        if matches!(libc::WSTOPSIG(st), libc::SIGSEGV | libc::SIGBUS)
                            && out.pc == RET_SENTINEL =>
                    {
                        self.restore(&saved)?;
                        Ok(out.regs[0])
                    }
                    Ok(out) => {
                        self.mark_unsafe();
                        Err(format!(
                            "remote call stopped abnormally sig={} pc={:#x}; function exit path not skipped, process needs recovery",
                            libc::WSTOPSIG(st),
                            out.pc
                        ))
                    }
                    Err(e) => {
                        self.mark_unsafe();
                        Err(e)
                    }
                }
            }
            Ok(_) => {
                self.mark_unsafe();
                Err("thread exited or an unexpected event occurred during the remote call".into())
            }
            Err(e) => {
                self.mark_unsafe();
                let _ = ptrace(PTRACE_INTERRUPT, self.pid, 0, 0);
                let parked = stopped_until(self.pid, Instant::now() + Duration::from_secs(2));
                if parked.is_ok() {
                    self.main_running.set(false);
                }
                Err(format!(
                    "{}; not restoring the PC still inside the function, stopped execution state={}",
                    e,
                    parked.is_ok()
                ))
            }
        }
    }
}
impl Drop for Remote {
    fn drop(&mut self) {
        if let Err(e) = self.detach_all() {
            eprintln!("[!] {}", e);
        }
    }
}

// Diagnostic mode uses the same bounded thread-group lifecycle.
const PTRACE_SYSCALL: i64 = 24;
#[derive(Default)]
pub struct SyscallEvent {
    pub pid: i32,
    pub nr: u64,
    pub pc: u64,
}
pub fn syscall_trace<F: FnMut(&SyscallEvent, &[procfs::MapEnt])>(
    pids: &[i32],
    secs: u32,
    mut cb: F,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(secs as u64);
    let mut remotes = Vec::new();
    for &pid in pids {
        let mut r = Remote::new(pid);
        r.seize_all()?;
        // TRACESYSGOOD, so that a syscall stop can be told apart from a real SIGTRAP.
        if ptrace(0x4200, pid, 0, 1) != 0 {
            return Err("failed to set TRACESYSGOOD".into());
        }
        if ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0 {
            return Err("failed to start syscall tracing".into());
        }
        r.stopped.remove(&pid);
        remotes.push(r);
    }
    while Instant::now() < deadline {
        for r in &remotes {
            let mut st = 0;
            if waitpid(r.pid, &mut st, WALL | libc::WNOHANG) <= 0 {
                continue;
            }
            if libc::WIFSTOPPED(st) {
                let sig = libc::WSTOPSIG(st);
                if sig == (libc::SIGTRAP | 0x80) {
                    let regs = r.getregs()?;
                    cb(
                        &SyscallEvent {
                            pid: r.pid,
                            nr: regs.regs[8],
                            pc: regs.pc,
                        },
                        &procfs::maps(r.pid).unwrap_or_default(),
                    );
                }
                let deliver = if sig == (libc::SIGTRAP | 0x80) {
                    0
                } else {
                    sig as u64
                };
                if ptrace(PTRACE_SYSCALL, r.pid, 0, deliver) != 0 {
                    return Err("failed to resume syscall tracing".into());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    for r in &mut remotes {
        r.detach_all()?;
    }
    Ok(())
}

/// Locate the carrier base inside the target process and return
/// (carrier_base, state_addr, setup_addr).
/// The GNU build-id is verified after the ident scan. The GOT reverse lookup exists only to
/// recognize an old carrier and refuse incompatible operations on it.
pub fn find_carrier(
    pid: i32,
    carrier_file: &std::path::Path,
    ident: &str,
) -> Result<Option<(u64, u64, u64)>, String> {
    if let Some(x) = find_via_ident(pid, carrier_file, ident)? {
        verify_build(pid, x.0, carrier_file)?;
        return Ok(Some(x));
    }
    find_via_got(pid, carrier_file)
}

/// A) scanning the ident content
fn find_via_ident(
    pid: i32,
    carrier_file: &std::path::Path,
    ident: &str,
) -> Result<Option<(u64, u64, u64)>, String> {
    let state_v =
        crate::elf::sym_vaddr(carrier_file, "g_state").ok_or("g_state symbol not found in carrier")?;
    let setup_v = crate::elf::sym_vaddr(carrier_file, "ij2art_setup")
        .ok_or("ij2art_setup symbol not found in carrier")?;

    let maps = procfs::maps(pid).map_err(|e| e.to_string())?;
    // Search the readable memfd segments for the ident string. Once it hits, aggregate over
    // the same inode to obtain the base address. Grouping has to be done by inode rather
    // than by path name, because the real jit-zygote-cache shipped with zygote has the same
    // name as ours.
    for m in maps
        .iter()
        .filter(|m| m.path.contains("memfd:") && m.flags.starts_with('r'))
    {
        let len = (m.end - m.start).min(8192) as usize;
        let mut buf = vec![0u8; len];
        if !procfs::vm_read(pid, m.start, &mut buf) {
            continue;
        }
        if find_subslice(&buf, ident.as_bytes()).is_none() {
            continue;
        }
        let base = maps
            .iter()
            .filter(|x| x.inode == m.inode && m.inode != 0)
            .map(|x| x.start)
            .min()
            .unwrap();
        return Ok(Some((base, base + state_v, base + setup_v)));
    }
    Ok(None)
}

/// B) GOT reverse lookup: in zygote and in pool members the GOT slot of the hook always
///    points into carrier .text. A .text fingerprint (the first 32 bytes of the setup
///    function) is then used for version verification, so that an old and a new version
///    cannot be mismatched and called incorrectly.
fn find_via_got(
    pid: i32,
    carrier_file: &std::path::Path,
) -> Result<Option<(u64, u64, u64)>, String> {
    let state_v =
        crate::elf::sym_vaddr(carrier_file, "g_state").ok_or("g_state symbol not found in carrier")?;
    let setup_v = crate::elf::sym_vaddr(carrier_file, "ij2art_setup")
        .ok_or("ij2art_setup symbol not found in carrier")?;

    let Some(base) = got_base(pid)? else {
        return Ok(None);
    };
    verify_build(pid, base, carrier_file)?;
    Ok(Some((base, base + state_v, base + setup_v)))
}

/// Get the base address via the GOT reverse lookup (without the fingerprint verification)
fn got_base(pid: i32) -> Result<Option<u64>, String> {
    let maps = procfs::maps(pid).map_err(|e| e.to_string())?;
    let Some((libar_path, libar_base)) = procfs::lib_base(&maps, "/libandroid_runtime.so") else {
        return Ok(None);
    };
    // The section headers on disk are preferred; for a library whose section headers have
    // been stripped, fall back to the remote PT_DYNAMIC, which returns absolute slot
    // addresses at runtime.
    let slot_addr =
        match crate::elf::got_reloc_offsets_checked(&libar_path, "selinux_android_setcontext") {
            Some(v) => v.first().map(|&off| libar_base + off),
            None => crate::elf::MemElf::load(pid, libar_base)
                .and_then(|mut m| m.reloc_slots("selinux_android_setcontext"))
                .and_then(|v| v.first().copied()),
        };
    let Some(slot_addr) = slot_addr else {
        return Ok(None);
    };
    let mut sb = [0u8; 8];
    if !procfs::vm_read(pid, slot_addr, &mut sb) {
        return Ok(None);
    }
    let slot_val = u64::from_ne_bytes(sb) & !0xff00_0000_0000_0000;

    // The slot value has to land inside the r-xp segment of some memfd; otherwise it is the
    // original address of an unhooked slot, which means that nothing has been injected.
    let Some(m) = maps.iter().find(|m| {
        slot_val >= m.start
            && slot_val < m.end
            && m.flags.contains('x')
            && m.path.contains("memfd:")
    }) else {
        return Ok(None);
    };
    let base = maps
        .iter()
        .filter(|x| x.inode == m.inode && m.inode != 0)
        .map(|x| x.start)
        .min()
        .unwrap();
    Ok(Some(base))
}

/// Lenient location, without the .text fingerprint verification. This is meant for the
/// rollback case, where a half-injected or old carrier may not match the local build.
pub fn find_carrier_lenient(
    pid: i32,
    carrier_file: &std::path::Path,
    ident: &str,
) -> Result<Option<u64>, String> {
    if let Some((base, _, _)) = find_via_ident(pid, carrier_file, ident)? {
        return Ok(Some(base));
    }
    got_base(pid)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn verify_build(pid: i32, base: u64, file: &std::path::Path) -> Result<(), String> {
    let (offset, expected) =
        crate::elf::build_id(file).ok_or("carrier is missing the GNU build-id; rebuild it")?;
    let mut actual = vec![0; expected.len()];
    if !procfs::vm_read(pid, base + offset, &mut actual) || actual != expected {
        return Err("carrier build mismatch; keeping the execution state, process it with the original build before injecting again".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    #[derive(Clone, Copy)]
    enum Mode {
        Return,
        ReturnBus,
        ReturnTbi,
        Fault,
        Timeout,
        RestoreFailure,
        CaptureFailure,
    }
    struct Trace {
        regs: Regs,
        fp: Vec<u8>,
        sve: Vec<u8>,
        mask: u64,
        mode: Mode,
        continued: bool,
        gpr_writes: usize,
        events: VecDeque<i32>,
    }
    thread_local! { static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) }; }
    fn errno(n: i32) {
        unsafe {
            #[cfg(target_os = "macos")]
            {
                *libc::__error() = n;
            }
            #[cfg(target_os = "linux")]
            {
                *libc::__errno_location() = n;
            }
            #[cfg(target_os = "android")]
            {
                *libc::__errno() = n;
            }
        }
    }
    pub(super) fn mock_ptrace(req: i64, _: i32, kind: u64, data: u64) -> Option<i64> {
        TRACE.with(|cell| {
            let mut guard = cell.borrow_mut();
            let t = guard.as_mut()?;
            let ret = unsafe {
                match req {
                    PTRACE_GETREGSET => {
                        let io = &mut *(data as *mut libc::iovec);
                        if kind == NT_PRFPREG && matches!(t.mode, Mode::CaptureFailure) {
                            errno(libc::EIO);
                            return Some(-1);
                        }
                        let bytes = match kind {
                            NT_PRSTATUS => core::slice::from_raw_parts(
                                &t.regs as *const _ as *const u8,
                                core::mem::size_of::<Regs>(),
                            ),
                            NT_PRFPREG => &t.fp,
                            NT_ARM_SVE => &t.sve,
                            _ => {
                                errno(libc::EINVAL);
                                return Some(-1);
                            }
                        };
                        let n = io.iov_len.min(bytes.len());
                        core::ptr::copy_nonoverlapping(bytes.as_ptr(), io.iov_base.cast(), n);
                        io.iov_len = n;
                        0
                    }
                    PTRACE_SETREGSET => {
                        let io = &*(data as *const libc::iovec);
                        let bytes =
                            core::slice::from_raw_parts(io.iov_base.cast::<u8>(), io.iov_len);
                        match kind {
                            NT_PRSTATUS => {
                                t.regs = core::ptr::read_unaligned(bytes.as_ptr().cast());
                                t.gpr_writes += 1;
                            }
                            NT_PRFPREG => {
                                if t.continued && matches!(t.mode, Mode::RestoreFailure) {
                                    errno(libc::EIO);
                                    return Some(-1);
                                }
                                t.fp.copy_from_slice(bytes);
                            }
                            NT_ARM_SVE => t.sve.copy_from_slice(bytes),
                            _ => panic!("unexpected regset"),
                        }
                        0
                    }
                    PTRACE_GETSIGMASK => {
                        *(data as *mut u64) = t.mask;
                        0
                    }
                    PTRACE_SETSIGMASK => {
                        t.mask = *(data as *const u64);
                        0
                    }
                    PTRACE_CONT => {
                        t.continued = true;
                        t.fp.fill(0xcc);
                        t.sve[16..].fill(0xdd);
                        t.regs.regs[0] = 0x1234;
                        match t.mode {
                            Mode::Fault => {
                                t.regs.pc = 0xbad;
                                t.events.push_back((libc::SIGBUS << 8) | 0x7f);
                            }
                            Mode::Timeout => {
                                t.regs.pc = 0xbeef;
                            }
                            _ => {
                                t.regs.pc = if matches!(t.mode, Mode::ReturnTbi) {
                                    ((t.regs.regs[30] << 8) as i64 >> 8) as u64
                                } else {
                                    t.regs.regs[30]
                                };
                                let signal = if matches!(t.mode, Mode::ReturnBus) {
                                    libc::SIGBUS
                                } else {
                                    libc::SIGSEGV
                                };
                                t.events.push_back((signal << 8) | 0x7f);
                            }
                        }
                        0
                    }
                    PTRACE_INTERRUPT => {
                        t.events.push_back((libc::SIGTRAP << 8) | 0x7f);
                        0
                    }
                    PTRACE_DETACH => 0,
                    _ => panic!("unexpected ptrace {req:#x}"),
                }
            };
            Some(ret)
        })
    }
    pub(super) fn mock_waitpid(tid: i32, status: &mut i32) -> Option<i32> {
        TRACE.with(|cell| {
            let mut guard = cell.borrow_mut();
            let t = guard.as_mut()?;
            if let Some(st) = t.events.pop_front() {
                *status = st;
                Some(tid)
            } else {
                Some(0)
            }
        })
    }
    fn prepare(mode: Mode) -> (Remote, Regs, Vec<u8>) {
        let mut original = Regs {
            sp: 0x10000,
            pc: 0x8000,
            pstate: 0x40000000,
            ..Default::default()
        };
        original.regs[0] = 99;
        let mut sve = vec![0x5a; 544];
        sve[..4].copy_from_slice(&544u32.to_ne_bytes());
        TRACE.with(|t| {
            *t.borrow_mut() = Some(Trace {
                regs: original,
                fp: vec![0x42; 528],
                sve: sve.clone(),
                mask: 0x123,
                mode,
                continued: false,
                gpr_writes: 0,
                events: VecDeque::new(),
            })
        });
        let mut remote = Remote::new(777777);
        remote.tids.push(remote.pid);
        remote.stopped.insert(remote.pid);
        remote.reset_timeout(Duration::from_millis(20));
        (remote, original, sve)
    }
    #[test]
    fn normal_return_restores_gpr_fp_sve_and_signal_mask() {
        let (r, original, sve) = prepare(Mode::Return);
        assert_eq!(r.call(0x9000, &[1, 2]).unwrap(), 0x1234);
        TRACE.with(|t| {
            let b = t.borrow();
            let t = b.as_ref().unwrap();
            assert_eq!(t.regs, original);
            assert_eq!(t.fp, vec![0x42; 528]);
            assert_eq!(t.sve, sve);
            assert_eq!(t.mask, 0x123);
        });
    }
    #[test]
    fn alignment_fault_at_return_sentinel_is_a_normal_return() {
        let (r, original, _) = prepare(Mode::ReturnBus);
        assert_eq!(r.call(0x9000, &[]).unwrap(), 0x1234);
        assert!(r.usable());
        TRACE.with(|t| assert_eq!(t.borrow().as_ref().unwrap().regs, original));
    }
    #[test]
    fn instruction_address_tag_normalization_preserves_return_sentinel() {
        let (r, original, _) = prepare(Mode::ReturnTbi);
        assert_eq!(r.call(0x9000, &[]).unwrap(), 0x1234);
        assert!(r.usable());
        TRACE.with(|t| assert_eq!(t.borrow().as_ref().unwrap().regs, original));
    }
    #[test]
    fn timeout_is_bounded_and_does_not_skip_the_active_function() {
        let (r, _, _) = prepare(Mode::Timeout);
        let start = Instant::now();
        assert!(r.call(0x9000, &[]).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!r.usable());
        assert!(r.call(0x9000, &[]).is_err());
        TRACE.with(|t| {
            let b = t.borrow();
            let t = b.as_ref().unwrap();
            assert_eq!(t.gpr_writes, 1);
            assert_eq!(t.regs.pc, 0xbeef);
        });
    }
    #[test]
    fn synchronous_fault_keeps_the_faulting_context() {
        let (r, _, _) = prepare(Mode::Fault);
        assert!(r.call(0x9000, &[]).is_err());
        assert!(!r.usable());
        TRACE.with(|t| assert_eq!(t.borrow().as_ref().unwrap().regs.pc, 0xbad));
    }
    #[test]
    fn restoration_failure_is_an_error_even_after_sentinel_return() {
        let (r, _, _) = prepare(Mode::RestoreFailure);
        assert!(r.call(0x9000, &[]).unwrap_err().contains("regset"));
        assert!(!r.usable());
    }
    #[test]
    fn missing_fp_state_refuses_call_before_modifying_target() {
        let (r, original, _) = prepare(Mode::CaptureFailure);
        assert!(r.call(0x9000, &[]).is_err());
        assert!(r.usable());
        TRACE.with(|t| {
            let b = t.borrow();
            let t = b.as_ref().unwrap();
            assert_eq!(t.regs, original);
            assert!(!t.continued);
            assert_eq!(t.gpr_writes, 0);
        });
    }
}
