//! Resources held by the injection transaction. The scratch address is not published to the
//! carrier, so a later `clear` cannot reuse an old address.
pub trait ResourceOps {
    fn close(&self, fd: i32) -> Result<(), String>;
    fn unhook(&self, addr: u64) -> Result<(), String>;
    fn dlclose(&self, handle: u64) -> Result<(), String>;
    fn munmap(&self, addr: u64) -> Result<(), String>;
    fn usable(&self) -> bool;
}

#[derive(Default)]
pub struct Resources {
    pub scratch: Option<u64>,
    pub fd: Option<i32>,
    pub handle: Option<u64>,
    pub unhook: Option<u64>,
    pub armed: bool,
}

impl Resources {
    /// With unload=false the commit succeeded and only the transport resources are
    /// released; on failure the hook has to be removed and then dlclose has to be called.
    pub fn cleanup(&mut self, ops: &impl ResourceOps, unload: bool) -> Result<(), String> {
        let mut errors = Vec::new();
        if !ops.usable() {
            return Err("remote call state unknown; keeping resources and the stopped execution state, cleanup must not continue".into());
        }
        if let Some(fd) = self.fd {
            match ops.close(fd) {
                Ok(()) => self.fd = None,
                Err(e) => errors.push(e),
            }
        }
        if unload && ops.usable() {
            if let Some(handle) = self.handle {
                let unhooked = if self.armed {
                    self.unhook
                        .ok_or_else(|| "missing a verified unhook address".to_string())
                        .and_then(|addr| ops.unhook(addr))
                } else {
                    Ok(())
                };
                match unhooked {
                    Ok(()) => {
                        self.armed = false;
                        match ops.dlclose(handle) {
                            Ok(()) => self.handle = None,
                            Err(e) => errors.push(e),
                        }
                    }
                    Err(e) => errors.push(e),
                }
            }
        }
        if ops.usable() {
            if let Some(addr) = self.scratch {
                match ops.munmap(addr) {
                    Ok(()) => self.scratch = None,
                    Err(e) => errors.push(e),
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    #[derive(Default)]
    struct Ops {
        log: RefCell<Vec<String>>,
        fail_unhook: bool,
        timeout: bool,
        unusable: Cell<bool>,
    }
    impl ResourceOps for Ops {
        fn close(&self, fd: i32) -> Result<(), String> {
            self.log.borrow_mut().push(format!("close {fd}"));
            Ok(())
        }
        fn unhook(&self, _: u64) -> Result<(), String> {
            self.log.borrow_mut().push("unhook".into());
            if self.timeout {
                self.unusable.set(true);
            }
            if self.fail_unhook || self.timeout {
                Err("unhook failed".into())
            } else {
                Ok(())
            }
        }
        fn dlclose(&self, _: u64) -> Result<(), String> {
            self.log.borrow_mut().push("dlclose".into());
            Ok(())
        }
        fn munmap(&self, addr: u64) -> Result<(), String> {
            self.log.borrow_mut().push(format!("munmap {addr}"));
            Ok(())
        }
        fn usable(&self) -> bool {
            !self.unusable.get()
        }
    }
    #[test]
    fn every_ordinary_failure_stage_releases_owned_resources() {
        for stage in 0..4 {
            let ops = Ops::default();
            let mut r = Resources {
                scratch: Some(4096),
                fd: (stage >= 1).then_some(7),
                handle: (stage >= 2).then_some(99),
                unhook: Some(123),
                armed: stage >= 3,
            };
            r.cleanup(&ops, true).unwrap();
            assert!(r.scratch.is_none() && r.fd.is_none() && r.handle.is_none());
            let log = ops.log.borrow();
            assert_eq!(log.last().unwrap(), "munmap 4096");
            if stage >= 3 {
                assert!(
                    log.iter().position(|s| s == "unhook")
                        < log.iter().position(|s| s == "dlclose")
                );
            }
        }
    }
    #[test]
    fn released_scratch_cannot_be_unmapped_again_after_address_reuse() {
        let ops = Ops::default();
        let mut r = Resources {
            scratch: Some(4096),
            handle: Some(99),
            ..Default::default()
        };
        r.cleanup(&ops, false).unwrap();
        // Assume the same address has by now been reused by a new mapping in the target, so
        // that the second cleanup pass no longer owns it.
        r.cleanup(&ops, true).unwrap();
        assert_eq!(
            ops.log
                .borrow()
                .iter()
                .filter(|s| s.starts_with("munmap"))
                .count(),
            1
        );
    }
    #[test]
    fn failed_unhook_never_unloads_code_but_still_releases_scratch() {
        let ops = Ops {
            fail_unhook: true,
            ..Default::default()
        };
        let mut r = Resources {
            scratch: Some(4096),
            handle: Some(99),
            unhook: Some(123),
            armed: true,
            ..Default::default()
        };
        assert!(r.cleanup(&ops, true).is_err());
        assert_eq!(r.handle, Some(99));
        assert!(r.scratch.is_none());
        assert!(!ops.log.borrow().contains(&"dlclose".into()));
    }
    #[test]
    fn interrupted_remote_call_disables_all_followup_cleanup() {
        let ops = Ops {
            timeout: true,
            ..Default::default()
        };
        let mut r = Resources {
            scratch: Some(4096),
            handle: Some(99),
            unhook: Some(123),
            armed: true,
            ..Default::default()
        };
        assert!(r.cleanup(&ops, true).is_err());
        assert_eq!(&*ops.log.borrow(), &["unhook"]);
        assert_eq!(r.scratch, Some(4096));
    }
}
