//! Closed-loop self-check using the real BPF programs and the real consumer; it tracks only
//! its own openat calls.
use super::{EvSys, EV_SYS_ENTER, EV_SYS_EXIT};

const OPENAT_NR: u64 = 56; // this project's BPF pt_regs layout and syscall numbers are arm64
const PATH: &[u8] = b"/dev/null\0";

struct Expected {
    marker: u64,
    path_ptr: u64,
    flags: u64,
    fd: i64,
    entered: bool,
}

struct Verification {
    pid: u32,
    tid: u32,
    executable: Vec<(u64, u64)>,
    expected: Option<Expected>,
    pairs: usize,
    last_ts: u64,
}

impl Verification {
    fn accept(&mut self, ev: &EvSys) -> Result<(), String> {
        let expected = self.expected.as_mut().ok_or("received extra/duplicate event")?;
        if ev.hdr.pid != self.pid || ev.hdr.tid != self.tid || ev.hdr.aux != OPENAT_NR {
            return Err(format!(
                "event identity mismatch: pid={} tid={} nr={}",
                ev.hdr.pid, ev.hdr.tid, ev.hdr.aux
            ));
        }
        if ev.hdr.status != 0 || ev.hdr.ts_ns == 0 || ev.hdr.ts_ns < self.last_ts {
            return Err(format!(
                "event status/timestamp mismatch: status={} ts={}",
                ev.hdr.status, ev.hdr.ts_ns
            ));
        }
        self.last_ts = ev.hdr.ts_ns;
        match ev.hdr.kind {
            EV_SYS_ENTER if !expected.entered => {
                let args = [
                    (-100i64) as u64,
                    expected.path_ptr,
                    expected.flags,
                    expected.marker,
                ];
                if ev.args[..4] != args {
                    return Err(format!(
                        "openat arguments mismatch: expected={args:x?} actual={:x?}",
                        &ev.args[..4]
                    ));
                }
                if ev.data_len as usize != PATH.len() || &ev.data[..PATH.len()] != PATH {
                    return Err("openat path decode mismatch".into());
                }
                if !self
                    .executable
                    .iter()
                    .any(|&(a, b)| (a..b).contains(&ev.hdr.pc))
                {
                    return Err(format!(
                        "user PC {:#x} not inside own executable mappings, check pt_regs offsets",
                        ev.hdr.pc
                    ));
                }
                expected.entered = true;
            }
            EV_SYS_EXIT if expected.entered => {
                if ev.ret != expected.fd {
                    return Err(format!(
                        "openat return value mismatch: expected={} actual={}",
                        expected.fd, ev.ret
                    ));
                }
                self.expected = None;
                self.pairs += 1;
            }
            _ => {
                return Err(format!(
                    "enter/exit out of order or duplicate event: kind={}",
                    ev.hdr.kind
                ))
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(super) fn run(object: &[u8]) -> Result<(), String> {
    use super::{attach_all, load_programs, map_fd, ring, sys, view};
    use std::cell::RefCell;
    use std::time::{Duration, Instant};

    if !cfg!(target_arch = "aarch64") {
        return Err("the current monitor syscall/pt_regs protocol only supports arm64".into());
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 || !(page as u32).is_power_of_two() {
        return Err(format!("cannot get a valid page size: {page}"));
    }
    // Unlike the 8 MiB used in the real mode, this also verifies that the capacity comes from
    // the map info rather than from a hardcoded constant.
    let capacity = (page as u32).max(64 * 1024);
    let calls = 1024usize.max(capacity as usize * 3 / (2 * 248) + 1);
    let pid = std::process::id();
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let executable = crate::procfs::maps(pid as i32)
        .map_err(|e| format!("own maps: {e}"))?
        .into_iter()
        .filter(|m| m.flags.contains('x'))
        .map(|m| (m.start, m.end))
        .collect();
    let (progs, maps) = load_programs(object, Some(capacity))?;
    if progs.len() != 2 {
        return Err(format!(
            "requires the two programs sys_enter/sys_exit, got {}",
            progs.len()
        ));
    }
    println!("[ok] {} real BPF programs passed the verifier", progs.len());
    super::seed_config(map_fd(&maps, "cfg_map")?)?;
    sys::map_update_bytes(
        map_fd(&maps, "policy_map")?,
        OPENAT_NR as u32,
        &[super::POL_DECODE, 1, 0, super::DEC_PATH, 1, 0, 0, 0],
        0,
    )
    .map_err(|e| format!("self-check policy: {e}"))?;
    let verification = RefCell::new(Verification {
        pid,
        tid,
        executable,
        expected: None,
        pairs: 0,
        last_ts: 0,
    });
    let mut ringbuf = ring::RingBuf::new(map_fd(&maps, "events_map")?, |rec| {
        verification.borrow_mut().accept(&view::decode(rec)?)
    })
    .map_err(|e| format!("libbpf ringbuf init: {e}"))?;
    println!("[ok] libbpf v1.7.0 ringbuf: capacity={capacity} page_size={page}");
    let links = attach_all(&progs).map_err(|e| format!("raw_tracepoint attach: {e}"))?;
    sys::map_update_bytes(map_fd(&maps, "tracked_map")?, pid, &1u32.to_ne_bytes(), 0)
        .map_err(|e| format!("self-check tracked: {e}"))?;
    println!("[ok] raw_tracepoint(sys_enter/sys_exit) attached, tracking only own pid={pid}");
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = (|| {
        for marker in 0..calls {
            // O_CREAT is not used, so this mode argument cannot change the file; giving each
            // round a distinct mode makes replayed old events recognizable.
            let flags = libc::O_RDONLY | libc::O_CLOEXEC;
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD as libc::c_long,
                    PATH.as_ptr(),
                    flags as libc::c_long,
                    marker as libc::c_long,
                )
            };
            if fd < 0 {
                return Err(format!("trigger openat: {}", std::io::Error::last_os_error()));
            }
            unsafe {
                libc::close(fd as i32);
            }
            verification.borrow_mut().expected = Some(Expected {
                marker: marker as u64,
                path_ptr: PATH.as_ptr() as u64,
                flags: flags as u64,
                fd: fd as i64,
                entered: false,
            });
            while verification.borrow().expected.is_some() {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "5s timeout: {}/{calls} event pairs completed",
                        verification.borrow().pairs
                    ));
                }
                ringbuf.poll(20)?;
            }
        }
        Ok(())
    })();
    drop(links); // On success, timeout, or decode failure alike, the probe is detached first;
    // the remaining resources are reclaimed by RAII.
    let stats = super::read_stats(map_fd(&maps, "stats_map")?)?;
    let counters = format!(
        "emitted: sys_enter={} sys_exit={} dropped: sys_enter={} sys_exit={}",
        stats[2], stats[4], stats[3], stats[5]
    );
    result.map_err(|e| format!("{e}; {counters}"))?;
    // All requested pairs have been completed, so any remainder left in the buffer must be
    // reported as an extra or duplicate event.
    ringbuf.consume()?;
    if stats[2] != calls as u64 || stats[4] != calls as u64 || stats[3] != 0 || stats[5] != 0 {
        return Err(format!(
            "event count inconsistent: expected={calls} pairs; {counters}"
        ));
    }
    println!("[ok] end-to-end openat: {calls} enter/exit pairs, path/args/return/user PC validated");
    println!(
        "[ok] ringbuf wraparound: {} rounds or more, received={}, {counters}",
        calls * 2 * 248 / capacity as usize,
        calls * 2
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Verification, EvSys) {
        let mut rec = [0u8; 240];
        rec[..4].copy_from_slice(&super::super::EVMAGIC.to_le_bytes());
        rec[4..6].copy_from_slice(&EV_SYS_ENTER.to_le_bytes());
        rec[6..8].copy_from_slice(&240u16.to_le_bytes());
        let mut ev = super::super::view::decode(&rec).unwrap();
        ev.hdr.pid = 123;
        ev.hdr.tid = 124;
        ev.hdr.aux = OPENAT_NR;
        ev.hdr.ts_ns = 1;
        ev.hdr.pc = 0x1010;
        ev.args[..4].copy_from_slice(&[(-100i64) as u64, 0x2000, 0, 7]);
        ev.data_len = PATH.len() as u16;
        ev.data[..PATH.len()].copy_from_slice(PATH);
        let state = Verification {
            pid: 123,
            tid: 124,
            executable: vec![(0x1000, 0x1100)],
            expected: Some(Expected {
                marker: 7,
                path_ptr: 0x2000,
                flags: 0,
                fd: 9,
                entered: false,
            }),
            pairs: 0,
            last_ts: 0,
        };
        (state, ev)
    }

    #[test]
    fn verifies_pair_and_rejects_replayed_record() {
        let (mut state, mut ev) = fixture();
        state.accept(&ev).unwrap();
        assert!(state.accept(&ev).is_err());
        ev.hdr.kind = EV_SYS_EXIT;
        ev.ret = 9;
        state.accept(&ev).unwrap();
        assert_eq!(state.pairs, 1);
        assert!(state.accept(&ev).is_err());
    }

    #[test]
    fn rejects_wrong_marker_pc_and_return_value() {
        let (mut state, mut ev) = fixture();
        ev.args[3] = 6;
        assert!(state.accept(&ev).is_err());
        ev.args[3] = 7;
        ev.hdr.pc = 0;
        assert!(state.accept(&ev).is_err());
        ev.hdr.pc = 0x1010;
        state.accept(&ev).unwrap();
        ev.hdr.kind = EV_SYS_EXIT;
        ev.ret = 8;
        assert!(state.accept(&ev).is_err());
    }

    // Fault injection mutates only this test process's own copy of the BPF object; neither the
    // on-disk artifact nor the target app is touched.
    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "android", target_os = "linux")
    ))]
    fn faulted_object(from: &[u8], to: &[u8]) -> Vec<u8> {
        assert_eq!(unsafe { libc::geteuid() }, 0, "requires root");
        assert_eq!(from.len(), to.len());
        let mut object = super::super::BPF_OBJECT.to_vec();
        let offsets: Vec<usize> = object
            .windows(from.len())
            .enumerate()
            .filter_map(|(i, bytes)| (bytes == from).then_some(i))
            .collect();
        assert_eq!(
            offsets.len(),
            2,
            "expected one patch in each syscall program"
        );
        for offset in offsets {
            object[offset..offset + to.len()].copy_from_slice(to);
        }
        object
    }

    #[test]
    #[ignore = "requires rooted arm64 Linux/Android, run with --test-threads=1"]
    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "android", target_os = "linux")
    ))]
    fn device_check_rejects_bad_magic() {
        let object = faulted_object(
            &super::super::EVMAGIC.to_le_bytes(),
            &(super::super::EVMAGIC ^ 1).to_le_bytes(),
        );
        let error = run(&object).unwrap_err();
        assert!(error.contains("magic"), "{error}");
    }

    #[test]
    #[ignore = "requires rooted arm64 Linux/Android, run with --test-threads=1"]
    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "android", target_os = "linux")
    ))]
    fn device_check_times_out_if_no_records_arrive() {
        // Replacing CALL bpf_ringbuf_submit(132) with bpf_ringbuf_discard(133) leaves the
        // emitted counter still growing and lets the map, verifier, and attach steps all
        // succeed, but no event is ever deliverable, so the check must fail with a timeout.
        let object = faulted_object(
            &[0x85, 0, 0, 0, 132, 0, 0, 0],
            &[0x85, 0, 0, 0, 133, 0, 0, 0],
        );
        let error = run(&object).unwrap_err();
        assert!(error.contains("timeout"), "{error}");
        assert!(error.contains("sys_enter=1 sys_exit=1"), "{error}");
    }
}
