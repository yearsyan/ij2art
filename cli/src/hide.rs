// Self-hide verification. The removal itself is performed inside the carrier constructor:
// the linker heap is normally mapped r-- and only becomes writable during the dlopen flow,
// so an external process cannot write to it (EFAULT has been confirmed on a real device).
// All this module does is a read-only check -- it walks the r_map chain again and confirms
// that our link_map is no longer on it.
use crate::procfs;
use crate::state::State;

// bionic link_map: l_next@24; r_debug: r_map@8
const LM_NEXT: u64 = 24;
const RD_RMAP: u64 = 8;
const TAG_MASK: u64 = 0x00ff_ffff_ffff_ffff;

fn rd64(pid: i32, addr: u64) -> Option<u64> {
    let mut b = [0u8; 8];
    if procfs::vm_read(pid, addr, &mut b) {
        Some(u64::from_ne_bytes(b) & TAG_MASK)
    } else {
        None
    }
}

pub fn verify_hidden(pid: i32, st: &State) -> Result<(), String> {
    let lm = st.self_link_map & TAG_MASK;
    let rd = st.r_debug & TAG_MASK;
    if lm == 0 || rd == 0 {
        return Err("state is missing self_link_map/r_debug".into());
    }
    let mut cur = rd64(pid, rd + RD_RMAP).ok_or("failed to read the r_map head")?;
    for _ in 0..1024 {
        if cur == 0 {
            return Ok(()); // The chain was walked to the end without meeting us -> hidden
        }
        if cur == lm {
            return Err("carrier is still on the r_map chain".into());
        }
        cur = rd64(pid, cur + LM_NEXT).ok_or("walk failed")?;
    }
    Err("r_map chain is invalid (more than 1024 nodes)".into())
}
