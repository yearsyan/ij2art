// Native inline hooks. Addresses belong to the target process; arm64 only.
#pragma once
#include "proto.h"

#define IJ2ART_CMD_INLINE_INIT 40u
#define IJ2ART_CMD_INLINE_ADD 41u
#define IJ2ART_CMD_INLINE_DEL 42u
#define IJ2ART_CMD_INLINE_LIST 43u
#define IJ2ART_CMD_INLINE_QUERY 44u

#define IJ2ART_E_INLINE_INVALID (-40)
#define IJ2ART_E_INLINE_STATE (-41)
#define IJ2ART_E_INLINE_LIMIT (-42)
#define IJ2ART_E_INLINE_BACKEND (-43)
#define IJ2ART_E_INLINE_NOT_FOUND (-44)

#define IJ2ART_INLINE_ACTIVE 1u
#define IJ2ART_INLINE_REMOVED 2u
#define IJ2ART_INLINE_ERROR 3u
#define IJ2ART_INLINE_SLOTS 128u

// ADD: addr=target, args[0]=replacement, args[1]=optional void** original slot.
// The slot must remain valid until removal; the backend publishes the original
// trampoline there BEFORE activating the hook. Proxy loads must use acquire.
// DEL/QUERY: addr=id. DEL requires caller quiescence, including proxy frames.
// Successful ADD/DEL/QUERY return one record; LIST returns all records, including
// removed/error records. IDs and records are retained until process exit.
struct ij2art_inline_info {
    uint64_t id;
    uint64_t target;
    uint64_t replacement;
    uint64_t original;
    uint64_t original_slot;
    uint32_t state;
    int32_t backend_error;
};
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_inline_info) == 48, inline_info_size);
IJ2ART_PROTO_ASSERT(IJ2ART_INLINE_SLOTS * sizeof(struct ij2art_inline_info) <=
                     IJ2ART_RSP_DATA_MAX, inline_list_fits);
