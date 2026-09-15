//! A raw wrapper around bpf(2). The field offsets are transcribed from the union bpf_attr in
//! third_party/kernel-uapi/include/linux/bpf.h (v5.10), and they must be rechecked whenever
//! the vendored header version changes.
#![allow(clippy::missing_safety_doc)]

use std::io;
use std::os::raw::c_char;
use std::os::unix::io::RawFd;

// enum bpf_cmd
pub const BPF_MAP_CREATE: libc::c_ulong = 0;
pub const BPF_MAP_LOOKUP_ELEM: libc::c_ulong = 1;
pub const BPF_MAP_UPDATE_ELEM: libc::c_ulong = 2;
pub const BPF_PROG_LOAD: libc::c_ulong = 5;
pub const BPF_RAW_TRACEPOINT_OPEN: libc::c_ulong = 17;

// enum bpf_map_type (the in-object map definitions carry their own type; only the check path
// uses ringbuf here)
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
// enum bpf_prog_type
pub const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;

#[cfg(target_arch = "aarch64")]
const SYS_BPF: libc::c_long = 280;
#[cfg(all(target_os = "linux", not(target_arch = "aarch64")))]
const SYS_BPF: libc::c_long = libc::SYS_bpf as libc::c_long;

/// The union bpf_attr is filled in byte-wise (the layout comments correspond to the anonymous
/// structs in the vendored bpf.h) to avoid any cross-platform repr alignment disagreement. The
/// kernel copies min(user size, sizeof(union)), so passing only the length actually needed is
/// sufficient.
fn bpf_call(cmd: libc::c_ulong, attr: &mut [u8]) -> io::Result<i64> {
    let rc = unsafe {
        libc::syscall(
            SYS_BPF,
            cmd,
            attr.as_ptr() as *const libc::c_void,
            attr.len() as libc::c_uint,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn wr32(a: &mut [u8], off: usize, v: u32) {
    a[off..off + 4].copy_from_slice(&v.to_ne_bytes());
}
fn wr64(a: &mut [u8], off: usize, v: u64) {
    a[off..off + 8].copy_from_slice(&v.to_ne_bytes());
}

/// BPF_MAP_CREATE: type@0 key@4 value@8 max@12 flags@16
pub fn map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> io::Result<RawFd> {
    let mut a = [0u8; 20];
    wr32(&mut a, 0, map_type);
    wr32(&mut a, 4, key_size);
    wr32(&mut a, 8, value_size);
    wr32(&mut a, 12, max_entries);
    wr32(&mut a, 16, map_flags);
    bpf_call(BPF_MAP_CREATE, &mut a).map(|fd| fd as RawFd)
}

/// BPF_MAP_UPDATE_ELEM: map_fd@0 key@8 value@16 flags@24 (key at 8 due to __aligned_u64)
pub fn map_update(fd: RawFd, key: *const u8, value: *const u8, flags: u64) -> io::Result<()> {
    let mut a = [0u8; 32];
    wr32(&mut a, 0, fd as u32);
    wr64(&mut a, 8, key as u64);
    wr64(&mut a, 16, value as u64);
    wr64(&mut a, 24, flags);
    bpf_call(BPF_MAP_UPDATE_ELEM, &mut a).map(|_| ())
}

/// BPF_MAP_LOOKUP_ELEM: the layout is the same as for update, with value as the out parameter
pub fn map_lookup(fd: RawFd, key: *const u8, value: *mut u8) -> io::Result<()> {
    let mut a = [0u8; 32];
    wr32(&mut a, 0, fd as u32);
    wr64(&mut a, 8, key as u64);
    wr64(&mut a, 16, value as u64);
    bpf_call(BPF_MAP_LOOKUP_ELEM, &mut a).map(|_| ())
}

pub fn map_update_bytes(fd: RawFd, key: u32, value: &[u8], flags: u64) -> io::Result<()> {
    map_update(fd, key.to_ne_bytes().as_ptr(), value.as_ptr(), flags)
}

pub fn map_update_u64(fd: RawFd, key: u32, value: u64, flags: u64) -> io::Result<()> {
    map_update(fd, key.to_ne_bytes().as_ptr(), value.to_ne_bytes().as_ptr(), flags)
}

pub fn map_lookup_u64(fd: RawFd, key: u32) -> Option<u64> {
    let key = key.to_ne_bytes();
    let mut val = [0u8; 8];
    map_lookup(fd, key.as_ptr(), val.as_mut_ptr()).ok()?;
    Some(u64::from_ne_bytes(val))
}

/// BPF_PROG_LOAD: type@0 cnt@4 insns@8 license@16 log_level@24 log_size@28 log_buf@32.
/// On failure, the verifier log (as a truncated tail) is carried into the error string.
pub fn prog_load(prog_type: u32, insns: &[u8], license: &[u8]) -> io::Result<RawFd> {
    let mut log = vec![0u8; 64 * 1024];
    let mut a = [0u8; 40];
    wr32(&mut a, 0, prog_type);
    wr32(&mut a, 4, (insns.len() / 8) as u32);
    wr64(&mut a, 8, insns.as_ptr() as u64);
    wr64(&mut a, 16, license.as_ptr() as u64);
    wr32(&mut a, 24, 1); // log_level
    wr32(&mut a, 28, log.len() as u32);
    wr64(&mut a, 32, log.as_mut_ptr() as u64);
    match bpf_call(BPF_PROG_LOAD, &mut a) {
        Ok(fd) => Ok(fd as RawFd),
        Err(e) => {
            let tail = log_tail(&log, 2048);
            if tail.is_empty() {
                Err(e)
            } else {
                Err(io::Error::new(
                    e.kind(),
                    format!("{} | verifier: {}", e, tail),
                ))
            }
        }
    }
}

/// BPF_RAW_TRACEPOINT_OPEN: name@0 prog_fd@8
pub fn raw_tp_open(name: &str, prog_fd: RawFd) -> io::Result<RawFd> {
    let mut namebuf = [0 as c_char; 64];
    let bytes = name.as_bytes();
    if bytes.len() >= namebuf.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "tracepoint name too long"));
    }
    for (i, &b) in bytes.iter().enumerate() {
        namebuf[i] = b as c_char;
    }
    let mut a = [0u8; 16];
    wr64(&mut a, 0, namebuf.as_ptr() as u64);
    wr32(&mut a, 8, prog_fd as u32);
    bpf_call(BPF_RAW_TRACEPOINT_OPEN, &mut a).map(|fd| fd as RawFd)
}

fn log_tail(log: &[u8], max: usize) -> String {
    let end = log.iter().position(|&c| c == 0).unwrap_or(log.len());
    let start = end.saturating_sub(max);
    String::from_utf8_lossy(&log[start..end]).into_owned()
}
