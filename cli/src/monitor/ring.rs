//! A thin wrapper over libbpf v1.7.0's ring buffer; mmap, wraparound, and memory ordering are
//! all handled by the original C module.
//! The fd must stay open for the whole lifetime of the RingBuf, and a single map may have only
//! one consumer.
use std::ffi::c_void;
use std::io;
use std::os::unix::io::RawFd;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::NonNull;

extern "C" {
    fn ring_buffer__new(
        fd: libc::c_int,
        callback: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> libc::c_int,
        ctx: *mut c_void,
        opts: *const c_void,
    ) -> *mut c_void;
    fn ring_buffer__free(rb: *mut c_void);
    fn ring_buffer__epoll_fd(rb: *const c_void) -> libc::c_int;
    fn ring_buffer__consume_n(rb: *mut c_void, n: usize) -> libc::c_int;
}

struct Callback<F> {
    deliver: F,
    error: Option<String>,
}

pub struct RingBuf<F> {
    raw: NonNull<c_void>,
    // The address of a Box is stable, so the ctx stored by C remains valid until free.
    callback: Box<Callback<F>>,
}

unsafe extern "C" fn deliver<F: FnMut(&[u8]) -> Result<(), String>>(
    ctx: *mut c_void,
    data: *mut c_void,
    len: usize,
) -> libc::c_int {
    let callback = &mut *ctx.cast::<Callback<F>>();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if data.is_null() || len > isize::MAX as usize {
            return Err("libbpf returned invalid event address/length".into());
        }
        // The borrow lives only until the callback returns; libbpf publishes consumer_pos
        // only after that.
        (callback.deliver)(std::slice::from_raw_parts(data.cast::<u8>(), len))
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            callback.error = Some(e);
            -libc::EBADMSG
        }
        Err(_) => {
            // A Rust unwind must not cross the C ABI boundary.
            callback.error = Some("ringbuf callback panicked".into());
            -libc::ECANCELED
        }
    }
}

impl<F: FnMut(&[u8]) -> Result<(), String>> RingBuf<F> {
    pub fn new(fd: RawFd, deliver_fn: F) -> io::Result<Self> {
        let mut callback = Box::new(Callback {
            deliver: deliver_fn,
            error: None,
        });
        let raw = unsafe {
            ring_buffer__new(
                fd,
                deliver::<F>,
                (&mut *callback as *mut Callback<F>).cast(),
                std::ptr::null(),
            )
        };
        let raw = NonNull::new(raw).ok_or_else(io::Error::last_os_error)?;
        Ok(Self { raw, callback })
    }

    pub fn poll(&mut self, timeout_ms: i32) -> Result<usize, String> {
        // libbpf's own poll() keeps consuming until it has caught up with the producer, so
        // under a sustained flood it may never return. Instead, wait on the epoll fd it
        // provides and then consume in bounded batches through consume_n; this guarantees that
        // the main loop can still flush its output and check --secs/SIGINT, and that the memory
        // used by one batch stays bounded.
        let mut pfd = libc::pollfd {
            fd: unsafe { ring_buffer__epoll_fd(self.raw.as_ptr()) },
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, timeout_ms) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(format!("libbpf epoll fd wait failed: {error}"));
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(format!("libbpf epoll fd error: revents={:#x}", pfd.revents));
        }
        self.consume()
    }

    /// A bounded batch; on exit, stop the producer and then call this repeatedly until it
    /// returns 0.
    pub fn consume(&mut self) -> Result<usize, String> {
        let rc = unsafe { ring_buffer__consume_n(self.raw.as_ptr(), 4096) };
        self.result(rc)
    }

    fn result(&mut self, rc: i32) -> Result<usize, String> {
        if let Some(e) = self.callback.error.take() {
            return Err(format!("ringbuf event handling failed: {e}"));
        }
        if rc == -libc::EINTR {
            return Ok(0);
        }
        if rc < 0 {
            return Err(format!(
                "libbpf ringbuf: {}",
                io::Error::from_raw_os_error(-rc)
            ));
        }
        Ok(rc as usize)
    }
}

impl<F> Drop for RingBuf<F> {
    fn drop(&mut self) {
        unsafe { ring_buffer__free(self.raw.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_error_is_not_silently_accepted() {
        fn reject(_: &[u8]) -> Result<(), String> {
            Err("bad magic".into())
        }
        let mut callback = Callback {
            deliver: reject,
            error: None,
        };
        let mut data = [0u8; 8];
        unsafe fn invoke<F: FnMut(&[u8]) -> Result<(), String>>(
            callback: &mut Callback<F>,
            data: &mut [u8],
        ) -> i32 {
            deliver::<F>(
                (callback as *mut Callback<F>).cast(),
                data.as_mut_ptr().cast(),
                data.len(),
            )
        }
        assert_eq!(unsafe { invoke(&mut callback, &mut data) }, -libc::EBADMSG);
        assert_eq!(callback.error.as_deref(), Some("bad magic"));
    }
}
