// This file is strictly isomorphic to common/state.h, so a change on either side has to
// be mirrored on the other.
pub const MAGIC: u64 = 0x4534_5034_4152_5431;
pub const VERSION: u32 = 2;
pub const MAX_TARGETS: usize = 32;
pub const F_ALL_USER_APPS: u32 = 1;
pub const F_VERBOSE: u32 = 2;

pub const HOOK_OK: u32 = 1;

pub const OFF_FLAGS: u64 = 12;
pub const OFF_HANDLE: u64 = 4144;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct State {
    pub hook_installed: u32,
    pub version: u32,
    pub payload_fd: i32,
    pub flags: u32,
    pub targets_count: u32,
    pub targets: [[u8; 128]; MAX_TARGETS],
    pub self_link_map: u64,
    pub r_debug: u64,
    pub scratch_addr: u64,
    pub self_handle: u64,
    pub magic: u64,
}

const _: () = assert!(core::mem::size_of::<State>() == 4160);

impl State {
    pub fn targets(&self) -> Vec<String> {
        (0..self.targets_count.min(MAX_TARGETS as u32) as usize)
            .map(|i| {
                let end = self.targets[i].iter().position(|&b| b == 0).unwrap_or(128);
                String::from_utf8_lossy(&self.targets[i][..end]).into_owned()
            })
            .collect()
    }
}

// Serialize the configuration only, so that neither the struct padding nor the resource
// fields are ever written back into the process.
pub fn config_bytes(st: &State) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + MAX_TARGETS * 128);
    out.extend_from_slice(&st.flags.to_ne_bytes());
    out.extend_from_slice(&st.targets_count.to_ne_bytes());
    for name in &st.targets {
        out.extend_from_slice(name);
    }
    out
}
pub fn target_config(csv: &str, flags: u32) -> Vec<u8> {
    let mut out = vec![0u8; 8 + MAX_TARGETS * 128];
    out[..4].copy_from_slice(&flags.to_ne_bytes());
    let mut count = 0u32;
    for (i, name) in csv
        .split(',')
        .filter(|s| !s.is_empty())
        .take(MAX_TARGETS)
        .enumerate()
    {
        let n = name.len().min(127);
        out[8 + i * 128..8 + i * 128 + n].copy_from_slice(&name.as_bytes()[..n]);
        count += 1;
    }
    out[4..8].copy_from_slice(&count.to_ne_bytes());
    out
}
#[derive(Debug)]
pub struct ConfigFailure {
    pub message: String,
    pub unrestored: Vec<i32>,
}

/// The caller must first halt all producers and consumers. Writing magic=0 makes the
/// configuration invalid if the tracer exits midway, and a new configuration is published
/// only once it has been written in full; if an ordinary write fails, every process that
/// was already touched is rolled back.
pub fn commit_configs(
    changes: &[(i32, u64, Vec<u8>)],
    new: &[u8],
    mut write: impl FnMut(i32, u64, &[u8]) -> bool,
) -> Result<(), ConfigFailure> {
    let magic_delta = (core::mem::size_of::<State>() - 8) as u64 - OFF_FLAGS;
    let invalid = 0u64.to_ne_bytes();
    let valid = MAGIC.to_ne_bytes();
    let mut touched = 0;
    let success = (|| {
        for (pid, addr, _) in changes {
            touched += 1;
            if !write(*pid, *addr + magic_delta, &invalid) {
                return false;
            }
        }
        for (pid, addr, _) in changes {
            if !write(*pid, *addr, new) {
                return false;
            }
        }
        for (pid, addr, _) in changes {
            if !write(*pid, *addr + magic_delta, &valid) {
                return false;
            }
        }
        true
    })();
    if success {
        return Ok(());
    }
    let mut unrestored = Vec::new();
    for (pid, addr, old) in changes[..touched].iter().rev() {
        // A new configuration that has already been published is invalidated first, and
        // the old configuration is published again only after the data has been restored.
        let invalidated = write(*pid, *addr + magic_delta, &invalid);
        let restored = write(*pid, *addr, old);
        if !invalidated || !restored || !write(*pid, *addr + magic_delta, &valid) {
            unrestored.push(*pid);
        }
    }
    Err(ConfigFailure {
        message: if unrestored.is_empty() {
            "config write failed; all old configs restored".into()
        } else {
            format!("config write failed; processes that could not be restored remain stopped: {:?}", unrestored)
        },
        unrestored,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_write_is_rolled_back_before_old_config_is_published() {
        let old = target_config("old.app", F_ALL_USER_APPS);
        let new = target_config("new.app", 0);
        let changes = vec![(1, 100u64, old.clone()), (2, 200, old.clone())];
        let mut memory = [old.clone(), old.clone()];
        let mut valid = [true; 2];
        let mut failed = false;
        let result = commit_configs(&changes, &new, |pid, addr, data| {
            let i = pid as usize - 1;
            if addr == changes[i].1 {
                assert!(!valid[i], "must not be published yet when updating data");
                memory[i][..13].copy_from_slice(&data[..13]);
                if i == 1 && !failed {
                    failed = true;
                    return false;
                }
                memory[i].copy_from_slice(data);
            } else {
                valid[i] = data == MAGIC.to_ne_bytes();
            }
            true
        });
        assert!(result.unwrap_err().unrestored.is_empty());
        assert_eq!(memory, [old.clone(), old]);
        assert_eq!(valid, [true, true]);
    }
    #[test]
    fn successful_commit_invalidates_all_copies_before_writing() {
        let old = target_config("old", 0);
        let new = target_config("new", 0);
        let changes = vec![(1, 100u64, old.clone()), (2, 200, old)];
        let mut invalidated = 0;
        commit_configs(&changes, &new, |_, addr, data| {
            if addr == 100 || addr == 200 {
                assert_eq!(invalidated, 2);
            } else if data == [0u8; 8] {
                invalidated += 1;
            }
            true
        })
        .unwrap();
    }
    #[test]
    fn rollback_failure_identifies_process_that_must_remain_stopped() {
        let old = target_config("old", 0);
        let result = commit_configs(&[(7, 100, old)], &target_config("new", 0), |_, addr, _| {
            addr != 100
        });
        assert_eq!(result.unwrap_err().unrestored, vec![7]);
    }
}
