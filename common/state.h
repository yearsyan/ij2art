// The ij2art shared-state struct: the carrier (C++) and the CLI (Rust) must keep exactly
// the same memory layout. The CLI finds and reads/writes this struct inside zygote memory
// via ptrace, using it for idempotence detection and target configuration.
#pragma once
#include <stdint.h>

#define IJ2ART_MAGIC   0x4534503441525431ULL
#define IJ2ART_VERSION 2u
#define IJ2ART_MAX_TARGETS 32u

// flags
#define IJ2ART_F_ALL_USER_APPS (1u << 0)   // matches every user App (uid%100000 in [10000,20000))
#define IJ2ART_F_VERBOSE       (1u << 1)   // carrier diagnostic log (inject/targets --verbose)

// values of hook_installed
#define IJ2ART_HOOK_NONE    0u   // the constructor has not run yet
#define IJ2ART_HOOK_OK      1u   // setcontext has been hooked
#define IJ2ART_HOOK_NOLIB   2u   // libandroid_runtime was not found
#define IJ2ART_HOOK_NOSYM   (1u << 31)   // the GOT entry for setcontext was not found
#define IJ2ART_HOOK_SETCON  4u   // setcon (the USAP path) has been hooked (OR'ed with OK)

struct ij2art_state {
    uint32_t hook_installed;                     // offset 0,  written by the carrier constructor
    uint32_t version;                            // offset 4
    int32_t  payload_fd;                         // offset 8,  reserved (always -1 in embedded mode)
    uint32_t flags;                              // offset 12
    uint32_t targets_count;                      // offset 16
    char     targets[IJ2ART_MAX_TARGETS][128]; // offset 20
    uint64_t self_link_map;                      // offset 4120, reserved, always 0
                                                 //   (the linker chain is never modified)
    uint64_t r_debug;                            // offset 4128, reserved, always 0
    uint64_t scratch_addr;                       // offset 4136, reserved, always 0;
                                                 //   scratch is held only by the inject txn
    uint64_t self_handle;                        // offset 4144, the dlopen return value (written
                                                 //   during CLI injection), which lets
                                                 //   __loader_dlclose deregister cleanly with no
                                                 //   dead soinfo left behind
    uint64_t magic;                              // must be written last: a valid magic means the
                                                 //   config is complete
};

#define IJ2ART_STATE_OFF_FLAGS   12u
#define IJ2ART_STATE_OFF_COUNT   16u
#define IJ2ART_STATE_OFF_TARGETS 20u
#define IJ2ART_STATE_OFF_HANDLE  4144u

// layout assertions (C++ side; the Rust side has matching const asserts)
#define IJ2ART_STATIC_ASSERT(cond, msg) typedef char ij2art_sa_##msg[(cond) ? 1 : -1]
IJ2ART_STATIC_ASSERT(sizeof(struct ij2art_state) == 4160, state_size);
