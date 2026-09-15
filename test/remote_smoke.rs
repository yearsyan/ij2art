// It seizes only the --park child process that this program itself created; when the test ends
// it is responsible for terminating and reaping that child.
#![allow(dead_code)]
#[path = "../cli/src/elf.rs"]
mod elf;
#[path = "../cli/src/procfs.rs"]
mod procfs;
#[path = "../cli/src/remote.rs"]
mod remote;
use std::io::BufRead;
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn run() -> Result<(), String> {
    let exe = std::env::args().nth(1).ok_or("requires a lifecycle-test path")?;
    let mut child = Child(
        std::process::Command::new(exe)
            .arg("--park")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?,
    );
    let mut ready = String::new();
    std::io::BufReader::new(child.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .map_err(|e| e.to_string())?;
    if ready.trim() != "READY" {
        return Err("test child process not ready".into());
    }
    let pid = child.0.id() as i32;
    let maps = procfs::maps(pid).map_err(|e| e.to_string())?;
    let resolve = |lib: &str, symbol: &str| -> Result<u64, String> {
        let (path, base) = procfs::lib_base(&maps, lib).ok_or(format!("no {lib}"))?;
        elf::sym_vaddr(&path, symbol)
            .map(|v| base + v)
            .ok_or(format!("no {symbol}"))
    };
    let mut r = remote::Remote::new(pid);
    r.seize_all()?;
    let result = (|| {
        if r.call(resolve("/libc.so", "getpid")?, &[])? != pid as u64 {
            return Err("getpid wrong return value".into());
        }
        let scratch = r.call(
            resolve("/libc.so", "mmap")?,
            &[0, 65536, 3, 0x22, u64::MAX, 0],
        )?;
        if scratch == u64::MAX {
            return Err("mmap failed".into());
        }
        if !procfs::vm_write(pid, scratch, b"/ij2art-test-does-not-exist.so\0") {
            return Err("scratch write failed".into());
        }
        let h = r.call(
            resolve("/linker64", "__loader_dlopen")?,
            &[scratch, 2, resolve("/libdl.so", "dlopen")?],
        )?;
        if h != 0 {
            return Err("a missing library should return NULL".into());
        }
        if r.call(resolve("/libc.so", "munmap")?, &[scratch, 65536])? as i32 != 0 {
            return Err("scratch munmap failed".into());
        }
        Ok(())
    })();
    r.finish(result)?;
    println!("PASS: real ptrace getpid/mmap/dlopen(NULL)/munmap and context restoration");
    let mut r = remote::Remote::new(pid);
    r.seize_all()?;
    r.reset_timeout(std::time::Duration::from_millis(200));
    let result = r.call(resolve("/libc.so", "sleep")?, &[30]);
    if result.is_ok() || r.usable() {
        return Err("a long call should time out and invalidate the remote state".into());
    }
    let _ = r.finish(result);
    let mut stopped = false;
    for _ in 0..100 {
        let status =
            std::fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| e.to_string())?;
        stopped = status
            .lines()
            .any(|l| l.starts_with("State:") && l.contains('T'));
        if stopped {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    if !stopped {
        return Err("the process was not left stopped after a faulty call".into());
    }
    println!("PASS: real timeout preserves SIGSTOP; owned child will now be reaped");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}
