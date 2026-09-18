// arm64 instruction observation. Snapshots describe the state BEFORE the instruction.
#pragma once
#include "proto.h"

#define IJ2ART_CMD_PROBE_ADD 70u
#define IJ2ART_CMD_PROBE_DEL 71u
#define IJ2ART_CMD_PROBE_LIST 72u
#define IJ2ART_CMD_PROBE_QUERY 73u
#define IJ2ART_CMD_PROBE_READ 74u

#define IJ2ART_E_PROBE_INVALID (-70)
#define IJ2ART_E_PROBE_STATE (-71)
#define IJ2ART_E_PROBE_LIMIT (-72)
#define IJ2ART_E_PROBE_BACKEND (-73)
#define IJ2ART_E_PROBE_NOT_FOUND (-74)
#define IJ2ART_E_PROBE_BUSY (-75)

#define IJ2ART_PROBE_ACTIVE 1u
#define IJ2ART_PROBE_REMOVED 2u
#define IJ2ART_PROBE_ERROR 3u
#define IJ2ART_PROBE_LIMITED 4u // collection stopped; instruction patch still installed
#define IJ2ART_PROBE_SLOTS 64u
#define IJ2ART_PROBE_CAPACITY 256u
#define IJ2ART_PROBE_NO_CONDITION UINT32_MAX
#define IJ2ART_PROBE_CLOCK_FAILED 1u

// ADD: addr=instruction, args[0]=tid (0=any), args[1]=max matching hits (0=unlimited),
// args[2]=condition register x0..x30 or NO_CONDITION, args[3]=equality value.
// DEL/QUERY: addr=id. DEL physically restores code and requires caller quiescence,
// including any in-flight interceptor frames, just like inline del.
// IDs, buffers and file-backed ELF pins survive removal until process exit.
struct ij2art_probe_info {
    uint64_t id, target, max_hits, hits, captured, dropped, overwritten, condition_value;
    uint32_t tid, condition_reg, state;
    int32_t backend_error;
    uint32_t instruction, capacity; // original instruction word, before patching
};

struct ij2art_probe_event {
    uint64_t seq, hit, ts_ns; // per-probe publication sequence, matching hit, CLOCK_MONOTONIC
    uint32_t tid, flags;
    uint64_t pc, sp, nzcv; // only NZCV is captured, not the full architectural PSTATE
    uint64_t regs[31];    // x0..x30; x29=FP, x30=LR
};

// READ: addr=id, args[0]=exclusive sequence cursor (0=start), args[1]=batch limit
// (1..READ_MAX). Non-destructive: repeating the cursor is safe until overwritten.
// A cursor ahead of captured is invalid. lost counts overwritten records after the
// supplied cursor; dropped separately counts matching hits lost to writer contention.
struct ij2art_probe_batch {
    ij2art_probe_info info;
    uint64_t next_seq, lost;
    uint32_t count, more;
    // Followed by count ij2art_probe_event records.
};
#define IJ2ART_PROBE_READ_MAX 48u
IJ2ART_PROTO_ASSERT(sizeof(ij2art_probe_info) == 88, probe_info_size);
IJ2ART_PROTO_ASSERT(sizeof(ij2art_probe_event) == 304, probe_event_size);
IJ2ART_PROTO_ASSERT(sizeof(ij2art_probe_batch) == 112, probe_batch_size);
IJ2ART_PROTO_ASSERT(IJ2ART_PROBE_SLOTS * sizeof(ij2art_probe_info) <= IJ2ART_RSP_DATA_MAX,
                   probe_list_fits);
IJ2ART_PROTO_ASSERT(sizeof(ij2art_probe_batch) + IJ2ART_PROBE_READ_MAX *
                   sizeof(ij2art_probe_event) <= IJ2ART_RSP_DATA_MAX, probe_batch_fits);
