// Definitions shared with the BPF side of the monitor: the event layout, the map
// definitions and the cfg/stats slots.
// The layout is kept in sync with cli/src/monitor/mod.rs on both sides (the same discipline
// as common/proto.h: any change must be made on both sides).
#pragma once

#include <linux/bpf.h>
#include "bpf_helpers.h"

#define EVMAGIC 0x31564E45u // "ENV1" little-endian

// ev_hdr.kind
#define EV_SYS_ENTER 1
#define EV_SYS_EXIT 2

// ev_hdr.status
#define EVF_TRUNCATED 0x1u
#define EVF_READ_FAIL 0x2u

struct ev_hdr {
    __u32 magic;
    __u16 kind;
    __u16 len;
    __u32 cpu, pid, tid, status;
    __u64 ts_ns;
    __u64 pc;
    __u64 aux; // sys_*: the syscall nr
};
struct ev_sys {
    struct ev_hdr hdr; // 48
    __u64 args[6];     // 96  the user registers x0..x5
    __s64 ret;         // 104 used only by sys_exit
    __u64 fp[4];       // 136 frame-pointer chain lr (caller), 0 = none/too shallow
    __u16 data_len;    // 138
    __u8 data[96];     // 234 raw bytes of a path or a sockaddr
    __u8 pad[6];       // 240
};
_Static_assert(sizeof(struct ev_hdr) == 48, "ev_hdr size");
_Static_assert(sizeof(struct ev_sys) == 240, "ev_sys size");

// ---- policy: policy_map[nr] ----
#define POL_DROP 0
#define POL_HEAD 1
#define POL_DECODE 2

#define DEC_NONE 0
#define DEC_PATH 1
#define DEC_SOCKADDR 2

struct sys_policy {
    __u8 action;
    __u8 arg_idx;   // index of the DECODE target argument (0..5)
    __u8 len_src;   // reserved (the source of the length); SOCKADDR reads a fixed size by family
    __u8 decoder;
    __u8 track_ret; // 1 = sys_exit also emits an event (fd correlation, etc.)
    __u8 pad[3];
};
_Static_assert(sizeof(struct sys_policy) == 8, "sys_policy size");

// ---- cfg_map slots (u64) ----
#define CFG_PC_OFF 0 // offset of pt_regs.pc for an arm64 user process (default 256)
#define CFG_FP_OFF 1 // offset of pt_regs.regs[29] (fp) for an arm64 user process (default 232)
#define CFG_SLOTS 8

// ---- stats_map slots (u64): idx = kind*2 + (0 emitted / 1 dropped) ----
#define STATS_SLOTS 8

// ---- maps ----
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct bpf_map_def SEC("maps") tracked_map = {
    BPF_MAP_TYPE_HASH, 4, 4, 512, 0};
struct bpf_map_def SEC("maps") policy_map = {
    BPF_MAP_TYPE_ARRAY, 4, sizeof(struct sys_policy), 512, 0};
struct bpf_map_def SEC("maps") cfg_map = {
    BPF_MAP_TYPE_ARRAY, 4, 8, CFG_SLOTS, 0};
struct bpf_map_def SEC("maps") lastnr_map = {
    BPF_MAP_TYPE_HASH, 4, 4, 1024, 0}; // tid -> nr (only for calls that use track_ret)
struct bpf_map_def SEC("maps") stats_map = {
    BPF_MAP_TYPE_ARRAY, 4, 8, STATS_SLOTS, 0};
struct bpf_map_def SEC("maps") events_map = {
    BPF_MAP_TYPE_RINGBUF, 0, 0, 8 * 1024 * 1024, 0};
