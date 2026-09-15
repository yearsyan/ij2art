// The ij2art control-ring protocol: the payload (C++) and the CLI (Rust) share this
// memory layout, so both sides must always be changed together.
// Channel shape: inside the target App the payload calls memfd_create("jit-cache") to
// create a 64K shared region, maps it with MAP_SHARED and keeps the fd open; the CLI
// copies an fd for the same file with pidfd_getfd and maps it with MAP_SHARED as well,
// so both sides operate on the same physical pages. The command and the response each
// occupy one slot (a single request may be in flight), signalled with an increasing
// sequence number plus a shared futex:
//   CLI:     fill the command slot -> cmd_seq release+1 -> FUTEX_WAKE(cmd_seq)
//   payload: FUTEX_WAIT(cmd_seq) wakes -> execute -> fill the response slot ->
//            rsp_seq release=cmd_seq -> WAKE(rsp_seq)
// The futex uses plain (non-PRIVATE) semantics: a shared mapping is keyed on
// (inode, page offset), so the virtual addresses on the two sides are irrelevant.
#pragma once
#include <stdint.h>

#define IJ2ART_RING_MAGIC  0x453452494E473031ULL  // "E4RING01"
// This identifies the current memory layout only. Both ends compare it for strict
// equality; there is no parsing or negotiation for any other layout.
#define IJ2ART_PROTO_VER   4u

#define IJ2ART_RING_FDSIZE  0x10000u  // total size of the memfd (disguised as a small JIT cache)
#define IJ2ART_RING_HDR_OFF 0u
#define IJ2ART_RING_CMD_OFF 0x1000u   // command slot: one page
#define IJ2ART_RING_RSP_OFF 0x2000u   // response slot: four pages

// hdr.flags
#define IJ2ART_RMF_WORKER   (1u << 0)  // the worker thread is alive
#define IJ2ART_RMF_SHUTDOWN (1u << 1)  // SHUTDOWN has been received and the ring torn down

// command types
#define IJ2ART_CMD_PING     1u   // -> data: a descriptive string
#define IJ2ART_CMD_READ     2u   // addr,len -> data (process_vm_readv; bad address does not crash)
#define IJ2ART_CMD_WRITE    3u   // addr,len,data (read-only page gets temp W per maps, restored)
#define IJ2ART_CMD_CALL     4u   // addr=function, args_n, args[] -> retval (x0)
#define IJ2ART_CMD_MODS     5u   // -> data: an array of ij2art_modent
#define IJ2ART_CMD_SHUTDOWN 6u   // the worker exits + munmap the ring + close the fd (no reconnect)

// response status
#define IJ2ART_E_BADCMD (-1)
#define IJ2ART_E_FAULT  (-2)   // the address is unmapped or not writable
#define IJ2ART_E_2BIG   (-3)   // the length exceeds the slot capacity

// data capacity inside a slot
#define IJ2ART_CMD_DATA_MAX 3992u
#define IJ2ART_RSP_DATA_MAX 16344u

struct ij2art_ring_hdr {
    uint64_t magic;        // off 0: published as READY once the worker has finished init
    uint32_t version;      // off 8
    uint32_t hdr_len;      // off 12
    int32_t  pid;          // off 16: the process holding the payload
    uint32_t flags;        // off 20
    uint32_t cmd_seq;      // off 24: the CLI -> payload doorbell word (4-byte aligned)
    uint32_t rsp_seq;      // off 28: the payload -> CLI doorbell word
    uint64_t session_counter; // off 32: incremented after each CLI exclusive lock, never reused
    uint32_t reserved[22];    // off 40..127

};

// The CLI holds a process-level fcntl write lock on the fd for the whole connection.
// Once a command has been published it must not be overwritten until rsp_seq == cmd_seq.
struct ij2art_cmd {
    uint32_t type;        // off 0
    uint32_t id;          // off 4: the cmd_seq of this call
    uint64_t session;     // off 8: the full 64-bit connection identity
    uint32_t args_n;      // off 16
    uint32_t reserved;    // off 20
    uint64_t addr;        // off 24
    uint64_t len;         // off 32
    uint64_t args[8];     // off 40
    uint8_t data[IJ2ART_CMD_DATA_MAX]; // off 104
};

struct ij2art_rsp {
    uint32_t type;        // off 0
    uint32_t id;          // off 4
    int32_t status;       // off 8
    uint32_t flags;       // off 12: bit0 = truncated
    uint64_t retval;      // off 16
    uint64_t len;         // off 24
    uint64_t session;     // off 32
    uint8_t data[IJ2ART_RSP_DATA_MAX]; // off 40
};

// MODS response entry (fixed size of 112 bytes)
struct ij2art_modent {
    uint64_t base;
    char     name[104];
};

#define IJ2ART_PROTO_ASSERT(cond, msg) typedef char ij2art_pa_##msg[(cond) ? 1 : -1]
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_ring_hdr) == 128, hdr_size);
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_cmd) == 4096, cmd_size);
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_rsp) == 16384, rsp_size);
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_modent) == 112, modent_size);
