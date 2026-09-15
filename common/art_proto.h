// ART management payloads. All integers are little endian; no pointers cross this API.
#pragma once
#include "proto.h"

#define IJ2ART_CMD_DEX_BEGIN 20u
#define IJ2ART_CMD_DEX_CHUNK 21u
#define IJ2ART_CMD_DEX_COMMIT 22u
#define IJ2ART_CMD_DEX_QUERY 23u
#define IJ2ART_CMD_DEX_DROP 24u
#define IJ2ART_CMD_DEX_LIST 25u
#define IJ2ART_CMD_HOOK_INIT 30u
#define IJ2ART_CMD_HOOK_ADD 31u
#define IJ2ART_CMD_HOOK_DEL 32u
#define IJ2ART_CMD_HOOK_LIST 33u
#define IJ2ART_CMD_HOOK_QUERY 34u
#define IJ2ART_CMD_HOOK_UPDATE 35u

#define IJ2ART_E_INVALID (-10)
#define IJ2ART_E_NOT_READY (-11)
#define IJ2ART_E_NOT_FOUND (-12)
#define IJ2ART_E_STATE (-13)
#define IJ2ART_E_LIMIT (-14)
#define IJ2ART_E_JAVA (-15)
#define IJ2ART_E_UNSUPPORTED_ART (-16)
#define IJ2ART_E_SIGNATURE (-17)
#define IJ2ART_E_BUSY (-18)
#define IJ2ART_E_COVERAGE (-19)

#define IJ2ART_DEX_MAX (8u * 1024u * 1024u)
#define IJ2ART_DEX_TOTAL_MAX (32u * 1024u * 1024u)
#define IJ2ART_DEX_SLOTS 16u
#define IJ2ART_DEX_UPLOADING 1u
#define IJ2ART_DEX_READY 2u
#define IJ2ART_DEX_FAILED 3u
#define IJ2ART_COVERAGE_FULL 1u
#define IJ2ART_COVERAGE_ENTRY 2u
#define IJ2ART_METHOD_MAX 1024u

// DEX_BEGIN: len=total bytes, args[0]=nonzero client nonce (idempotency key).
// DEX_CHUNK: addr=dex_id, args[0]=offset, len=data length, data=bytes.
// COMMIT/DROP: addr=dex_id. QUERY: addr=dex_id OR args[0]=nonce.
// BEGIN/CHUNK/COMMIT/QUERY return this record; LIST returns an array.
struct ij2art_dex_info {
    uint64_t id;
    uint64_t nonce;
    uint64_t size;
    uint64_t received;
    uint32_t state;
    uint32_t hook_refs; // current + in-flight retired callback versions, including disabled Hooks
    int32_t error;
    uint32_t reserved;
};
// HOOK_ADD: addr=dex_id, args[0]=coverage; data is target_len:u32,
// replacement_len:u32 followed by two UTF-8 selectors (no NUL terminator).
// Selector: binary.class.Name.method(JVM-descriptor)return-descriptor.
// Target loader is the explicitly registered App loader; replacement must be
// declared by the referenced DEX loader. Upload never selects either method.
// HOOK_UPDATE: addr=hook_id, args[0]=dex_id, data=replacement selector (no NUL).
// Atomically selects a new callback version; existing invocations finish their
// leased version. Target/backup, hook id, counters and enabled state do not change.
//
// HOOK_INIT: args_n=0 selects the in-process backend. Legacy args_n=8 supplies
// CLI-resolved libart addresses for additional validation, in this order:
//   ScopedSuspendAll ctor/dtor, ScopedGCCriticalSection ctor/dtor,
//   Thread::CurrentFromGdb, ArtMethod::CopyFrom,
//   art_quick_generic_jni_trampoline, art_quick_to_interpreter_bridge.
// The payload accepts them only when the in-memory libart build-id matches a
// known adapter, every address lands inside an r-x mapping of libart, and each
// address equals the build-bound symbol RVA plus the verified libart load base.
#define IJ2ART_HOOK_ACTIVE   2u
#define IJ2ART_HOOK_DRAINING 3u
#define IJ2ART_HOOK_DISABLED 4u
// DEL is logical disable only: the target stays native, the JNI entry and backup
// remain installed. The current callback's DEX stays pinned until process exit;
// superseded versions release their DEX charge when their invocations finish.
// in_flight counts accepted replacements, not bypass calls or complete JNI frames.

// HOOK_ADD/UPDATE/QUERY/DEL return one record; LIST concatenates records.
// Each record is this fixed header followed by target and replacement
// selector bytes (no NUL); LIST sets rsp flags bit0 on truncation.
struct ij2art_hook_info {
    uint64_t id;
    uint64_t hits;
    uint64_t last_hit_ms;
    uint32_t state;
    uint32_t in_flight;
    uint16_t target_len;
    uint16_t replacement_len;
    uint32_t error;
    uint32_t coverage; // IJ2ART_COVERAGE_*; independently reported from safety admission
    uint32_t generation; // starts at 1; occupies the old header's trailing padding
};
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_hook_info) == 48, hook_info_size);
IJ2ART_PROTO_ASSERT(sizeof(struct ij2art_dex_info) == 48, dex_info_size);
