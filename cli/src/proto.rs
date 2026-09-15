// This file is strictly isomorphic to common/proto.h: the field offsets mirror that
// header exactly, so any change to one side must be applied to the other as well.
// Raw byte offsets are used rather than a repr(C) struct, which is consistent with the
// OFF_* style used in state.rs.
pub const RING_MAGIC: u64 = 0x4534_5249_4E47_3031;
// Match value for the current memory layout; this is the only layout that is accepted.
pub const PROTO_VER: u32 = 4;
pub const RING_FDSIZE: u64 = 0x10000;

pub const CMD_OFF: usize = 0x1000;
pub const RSP_OFF: usize = 0x2000;

// Field offsets within hdr
pub const H_MAGIC: usize = 0;
pub const H_VERSION: usize = 8;
pub const H_PID: usize = 16;
pub const H_FLAGS: usize = 20;
pub const H_CMD_SEQ: usize = 24;
pub const H_RSP_SEQ: usize = 28;
pub const H_SESS: usize = 32; // connection counter, an AtomicU64

// Field offsets within cmd
pub const C_TYPE: usize = 0;
pub const C_ID: usize = 4;
pub const C_SESS: usize = 8; // the full u64 session identity
pub const C_ARGSN: usize = 16;
pub const C_ADDR: usize = 24;
pub const C_LEN: usize = 32;
pub const C_ARGS: usize = 40;
pub const C_DATA: usize = 104;
pub const CMD_DATA_MAX: usize = 3992;

// Field offsets within rsp
pub const R_TYPE: usize = 0;
pub const R_ID: usize = 4;
pub const R_STATUS: usize = 8;
pub const R_FLAGS: usize = 12;
pub const R_RETVAL: usize = 16;
pub const R_LEN: usize = 24;
pub const R_SESSION: usize = 32;
pub const R_DATA: usize = 40;
pub const RSP_DATA_MAX: usize = 16344;

pub const CMD_PING: u32 = 1;
pub const CMD_READ: u32 = 2;
pub const CMD_WRITE: u32 = 3;
pub const CMD_CALL: u32 = 4;
pub const CMD_MODS: u32 = 5;
pub const CMD_SHUTDOWN: u32 = 6;

pub const MODENT_SIZE: usize = 112;

// Compile-time offset checks that mirror the static asserts in proto.h
const _: () = assert!(RSP_OFF + 0x4000 <= RING_FDSIZE as usize);
const _: () = assert!(C_DATA + CMD_DATA_MAX == 0x1000);
const _: () = assert!(R_DATA + RSP_DATA_MAX == 0x4000);

pub const RMF_WORKER: u32 = 1;
pub const RMF_SHUTDOWN: u32 = 2;
