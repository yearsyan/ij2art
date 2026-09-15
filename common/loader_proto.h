// Native library upload over the control ring: bytes are staged in a memfd and
// dlopen("/proc/self/fd/N") loads them in-process, so no on-disk path or SELinux
// exec label is needed. Mirrors the DEX begin/chunk/commit shape; addresses and
// handles belong to the target process.
#pragma once
#include "proto.h"

#define IJ2ART_CMD_LIB_BEGIN   50u  // args[0]=nonce, args[1]=total bytes, len/data=memfd name
#define IJ2ART_CMD_LIB_CHUNK   51u  // addr=lib_id, args[0]=offset, len/data=bytes
#define IJ2ART_CMD_LIB_COMMIT  52u  // addr=lib_id -> dlopen staged memfd
#define IJ2ART_CMD_LIB_UNLOAD  53u  // addr=lib_id -> dlclose (idempotent)
#define IJ2ART_CMD_LIB_LIST    54u  // -> data: ij2art_lib_info array

#define IJ2ART_E_LIB_INVALID   (-50)
#define IJ2ART_E_LIB_STATE     (-51)
#define IJ2ART_E_LIB_LIMIT     (-52)
#define IJ2ART_E_LIB_NOT_FOUND (-53)
#define IJ2ART_E_LIB_DLOPEN    (-54)
#define IJ2ART_E_LIB_IO        (-55)

#define IJ2ART_LIB_MAX       (4u * 1024u * 1024u)   // per-library byte cap
#define IJ2ART_LIB_TOTAL_MAX (16u * 1024u * 1024u)  // staging + loaded total
#define IJ2ART_LIB_SLOTS     8u
#define IJ2ART_LIB_NAME_MAX  48u  // [A-Za-z0-9._-]; shows up as /memfd:NAME (deleted)

#define IJ2ART_LIB_UPLOADING 1u
#define IJ2ART_LIB_LOADED    2u
#define IJ2ART_LIB_FAILED    3u   // reclaimed by a later BEGIN with a fresh nonce
#define IJ2ART_LIB_UNLOADED  4u

// BEGIN is idempotent on nonce: the same nonce+size+name returns the existing
// record, letting a timed-out CLI resume (replay chunks; overlap is verified).
// CHUNKs must arrive in order; a prefix overlap must carry identical bytes.
// COMMIT on LOADED is a no-op retry; UNLOAD on UNLOADED is a no-op.
// Records and IDs are retained until process exit. A FAILED upload keeps its
// error for LIST but the slot may be reused by a new BEGIN.
struct ij2art_lib_info {
    uint64_t id;
    uint64_t nonce;
    uint64_t size;
    uint64_t received;
    uint64_t base;    // dlopen'd load base (maps off==0 segment)
    uint64_t handle;  // dlopen handle kept for UNLOAD
    uint32_t state;   // IJ2ART_LIB_*
    int32_t  error;   // IJ2ART_E_LIB_* when FAILED
    char     name[64];
    uint8_t  reserved[8];
};
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_lib_info) == 128, lib_info_size);
IJ2ART_PROTO_ASSERT(IJ2ART_LIB_SLOTS * sizeof(struct ij2art_lib_info) <=
                     IJ2ART_RSP_DATA_MAX, lib_list_fits);
