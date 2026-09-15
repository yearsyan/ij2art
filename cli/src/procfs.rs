// /proc inspection plus process memory reads and writes through process_vm_readv and
// process_vm_writev, which require ptrace_may_access permission (satisfied under root).
use std::collections::HashSet;
use std::fs;
use std::io;

#[derive(Debug, Clone)]
pub struct MapEnt {
    pub start: u64,
    pub end: u64,
    pub flags: String,
    pub off: u64,
    pub inode: u64,
    pub path: String,
}

pub fn maps(pid: i32) -> io::Result<Vec<MapEnt>> {
    let text = fs::read_to_string(format!("/proc/{}/maps", pid))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(range), Some(flags), Some(off), Some(_dev), Some(inode)) =
            (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let path = it.collect::<Vec<_>>().join(" "); // a path may contain spaces, e.g. " (deleted)"
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        out.push(MapEnt {
            start: u64::from_str_radix(s, 16).unwrap_or(0),
            end: u64::from_str_radix(e, 16).unwrap_or(0),
            flags: flags.to_string(),
            off: u64::from_str_radix(off, 16).unwrap_or(0),
            inode: inode.parse().unwrap_or(0),
            path,
        });
    }
    Ok(out)
}

/// All zygote instances: the first field of cmdline is zygote64/zygote and the parent
/// process is init.
/// Note that Name in /proc/pid/status must not be used for this, because the zygote main
/// thread renames itself to "main". A single-instance device has only the primary zygote;
/// on some ROMs there is also a secondary instance serving ordinary third-party apps (for
/// example OPPO's zygote_ocomp), running alongside the primary one, so the instance has to
/// be selected according to the target before injecting.
pub fn zygote_candidates() -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return out;
    };
    for ent in dir.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let first = cmd.split(|&b| b == 0).next().unwrap_or(&[]);
        let first = core::str::from_utf8(first).unwrap_or("").trim();
        if first != "zygote64" && first != "zygote" {
            continue;
        }
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        if status.lines().any(|l| l == "PPid:\t1") {
            out.push(pid);
        }
    }
    out
}

/// The primary zygote: whichever process holds the /dev/socket/zygote listening socket is
/// the primary zygote.
/// A secondary zygote (for example zygote_ocomp) listens on its own socket instead, which
/// is irrelevant here.
fn primary_zygote(candidates: &[i32]) -> Option<i32> {
    if candidates.len() <= 1 {
        return candidates.first().copied();
    }
    let inode = zygote_socket_inode()?;
    let want = format!("socket:[{inode}]");
    candidates.iter().copied().find(|&c| {
        fs::read_dir(format!("/proc/{c}/fd"))
            .map(|d| {
                d.flatten().any(|e| {
                    fs::read_link(e.path())
                        .map(|l| l.to_string_lossy() == want)
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    })
}

fn cmdline_first(pid: i32) -> String {
    fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|cmd| {
            cmd.split(|&b| b == 0)
                .next()
                .map(|s| core::str::from_utf8(s).unwrap_or("").trim().to_string())
        })
        .unwrap_or_default()
}

fn ppid_of(pid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
}

pub struct ZygoteChoice {
    pub pid: i32,
    /// How the choice was made: sole = a single instance, target-parent = the parent of a
    /// running target, app-zygote = the primary instance was excluded, primary = backstop.
    pub how: &'static str,
}

/// Pick a zygote for the target, using rules in decreasing order of confidence:
/// 1. If the target process is already running, its parent is the zygote that will fork it
///    (even after USAP specialization the parent is still a zygote). If the targets belong
///    to more than one zygote, report an error and let the caller handle them one at a time
///    with --pid.
/// 2. With multiple instances, exclude the primary zygote that has a system_server child,
///    because ordinary third-party apps come from the secondary instance.
/// 3. With a single instance, use it directly; as a backstop, fall back to the primary
///    zygote, that is, the holder of /dev/socket/zygote.
pub fn choose_zygote(targets: &[String]) -> Result<ZygoteChoice, String> {
    let candidates = zygote_candidates();
    if candidates.is_empty() {
        return Err("zygote process not found".into());
    }
    let primary = primary_zygote(&candidates);
    // A single /proc scan collects both at once: the parent zygote of system_server and the
    // parent zygote of each running target.
    let mut ss_parents = HashSet::new();
    let mut target_parents = HashSet::new();
    if candidates.len() > 1 || !targets.is_empty() {
        let Ok(dir) = fs::read_dir("/proc") else {
            return Err("failed to read /proc".into());
        };
        for ent in dir.flatten() {
            let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let Some(ppid) = ppid_of(pid) else { continue };
            if !candidates.contains(&ppid) {
                continue; // only processes forked directly by a candidate are counted
            }
            let name = cmdline_first(pid);
            if name == "system_server" {
                ss_parents.insert(ppid);
            }
            if !name.is_empty() && targets.iter().any(|t| t == &name) {
                target_parents.insert(ppid);
            }
        }
    }
    let (pid, how) = decide(&candidates, primary, &ss_parents, &target_parents)?;
    Ok(ZygoteChoice { pid, how })
}

fn decide(
    candidates: &[i32],
    primary: Option<i32>,
    ss_parents: &HashSet<i32>,
    target_parents: &HashSet<i32>,
) -> Result<(i32, &'static str), String> {
    if target_parents.len() > 1 {
        let mut pids: Vec<_> = target_parents.iter().copied().collect();
        pids.sort_unstable();
        return Err(format!(
            "target processes span multiple zygotes({pids:?}); inject each separately with --pid"
        ));
    }
    if let Some(&z) = target_parents.iter().next() {
        return Ok((z, "target-parent"));
    }
    if candidates.len() == 1 {
        return Ok((candidates[0], "sole"));
    }
    let app_side: Vec<i32> = candidates
        .iter()
        .copied()
        .filter(|c| !ss_parents.contains(c))
        .collect();
    if app_side.len() == 1 {
        return Ok((app_side[0], "app-zygote"));
    }
    let fallback = primary.or_else(|| candidates.iter().copied().min());
    fallback.map(|z| (z, "primary")).ok_or_else(|| "zygote process not found".into())
}

/// Pre-forked children sitting in the USAP pool (their cmdline is usap64/usap32)
pub fn find_usaps() -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return out;
    };
    for ent in dir.flatten() {
        let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(cmd) = fs::read(format!("/proc/{}/cmdline", pid)) else {
            continue;
        };
        let first = cmd.split(|&b| b == 0).next().unwrap_or(&[]);
        if core::str::from_utf8(first)
            .unwrap_or("")
            .trim()
            .starts_with("usap")
        {
            out.push(pid);
        }
    }
    out
}

/// Find the base address of a library inside the process: the r--p header segment with
/// off==0 is the base, and the executable segment follows it (offset!=0).
pub fn lib_base(maps: &[MapEnt], suffix: &str) -> Option<(std::path::PathBuf, u64)> {
    let m = maps
        .iter()
        .find(|m| m.path.ends_with(suffix) && m.off == 0)?;
    Some((std::path::PathBuf::from(&m.path), m.start))
}

/// The inode of the /dev/socket/zygote listener entry in /proc/net/unix
fn zygote_socket_inode() -> Option<u64> {
    let text = fs::read_to_string("/proc/net/unix").ok()?;
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Num RefCount Protocol Flags Type St Inode Path
        if f.len() >= 8 && f[7] == "/dev/socket/zygote" && f[5] == "03" {
            if let Ok(ino) = f[6].parse::<u64>() {
                return Some(ino);
            }
        }
    }
    None
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn vm_read(pid: i32, addr: u64, buf: &mut [u8]) -> bool {
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut _,
        iov_len: buf.len(),
    };
    unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) == buf.len() as isize }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn vm_write(pid: i32, addr: u64, buf: &[u8]) -> bool {
    let local = libc::iovec {
        iov_base: buf.as_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut _,
        iov_len: buf.len(),
    };
    unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) == buf.len() as isize }
}

pub fn vm_read_struct<T: Copy>(pid: i32, addr: u64) -> Option<T> {
    let mut v: T = unsafe { core::mem::zeroed() };
    let n = core::mem::size_of::<T>();
    let slice = unsafe { core::slice::from_raw_parts_mut(&mut v as *mut T as *mut u8, n) };
    if vm_read(pid, addr, slice) {
        Some(v)
    } else {
        None
    }
}

/// Re-verify the process identity after it has been stopped, so that we do not keep a USAP
/// that has already turned into an App since it was enumerated.
pub fn is_unspecialized(pid: i32) -> bool {
    let cmd = fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
    matches!(
        cmd.split(|&b| b == 0).next().unwrap_or(&[]),
        b"zygote64" | b"zygote" | b"usap64" | b"usap32"
    )
}
pub fn is_usap_of(pid: i32, parent: i32) -> bool {
    let cmd = fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default();
    if !matches!(
        cmd.split(|&b| b == 0).next().unwrap_or(&[]),
        b"usap64" | b"usap32"
    ) {
        return false;
    }
    fs::read_to_string(format!("/proc/{}/status", pid))
        .unwrap_or_default()
        .lines()
        .any(|l| {
            l.strip_prefix("PPid:")
                .and_then(|s| s.trim().parse::<i32>().ok())
                == Some(parent)
        })
}
pub fn find_usaps_for(parent: i32) -> Vec<i32> {
    find_usaps()
        .into_iter()
        .filter(|&p| is_usap_of(p, parent))
        .collect()
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn vm_read(_: i32, _: u64, _: &mut [u8]) -> bool {
    false
}
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn vm_write(_: i32, _: u64, _: &[u8]) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[i32]) -> HashSet<i32> {
        items.iter().copied().collect()
    }

    #[test]
    fn sole_candidate_is_returned_directly() {
        assert_eq!(
            decide(&[42], Some(42), &set(&[42]), &set(&[])).unwrap(),
            (42, "sole")
        );
    }

    #[test]
    fn secondary_without_system_server_wins_on_multi_instance() {
        // The primary zygote always has a system_server child, so a candidate without one
        // is an app-side zygote.
        assert_eq!(
            decide(&[1213, 1215], Some(1213), &set(&[1213]), &set(&[])).unwrap(),
            (1215, "app-zygote")
        );
    }

    #[test]
    fn running_target_parent_is_authoritative() {
        // The target runs under the primary (for example a system app), so pick the primary
        // directly and skip the exclusion rule.
        assert_eq!(
            decide(&[1213, 1215], Some(1213), &set(&[1213]), &set(&[1213])).unwrap(),
            (1213, "target-parent")
        );
    }

    #[test]
    fn targets_spanning_zygotes_is_an_error() {
        let err = decide(&[1213, 1215], Some(1213), &set(&[1213]), &set(&[1213, 1215]))
            .unwrap_err();
        assert!(err.contains("--pid"), "{err}");
    }

    #[test]
    fn fallback_to_primary_when_no_candidate_is_app_side() {
        assert_eq!(
            decide(&[10, 20], Some(20), &set(&[10, 20]), &set(&[])).unwrap(),
            (20, "primary")
        );
    }
}
