// Hook-record serialization: the response filling for add/query/del/list all goes through
// this one place.
// Boundary discipline (review R4): prove that the cumulative length fits before writing
// anything. If it does not fit, only the truncation flag is set and not a single byte is
// written -- the old implementation checked the length of a single record, so accumulating
// several of them would write past the response slot.
#pragma once
#include "art_proto.h"
#include <string.h>
#include <string_view>

namespace ij2art {

struct HookRecordView {
    uint64_t id;
    uint64_t hits;
    uint64_t last_hit_ms;
    uint32_t state;
    uint32_t in_flight;
    std::string_view target;
    std::string_view replacement;
    uint32_t coverage = IJ2ART_COVERAGE_ENTRY;
    uint32_t generation = 1;
};

// Append one record to the response data area. Returns false on truncation (r.flags bit0
// is set and no bytes have been written).
inline bool append_hook_record(ij2art_rsp& r, const HookRecordView& rec) {
    if (rec.target.size() > 0xffff || rec.replacement.size() > 0xffff) {
        r.flags |= 1;  // length field is u16; oversize records truncation, never silent shortening
        return false;
    }
    ij2art_hook_info info{};
    info.id = rec.id;
    info.hits = rec.hits;
    info.last_hit_ms = rec.last_hit_ms;
    info.state = rec.state;
    info.coverage = rec.coverage;
    info.generation = rec.generation;
    info.in_flight = rec.in_flight;
    info.target_len = (uint16_t)rec.target.size();
    info.replacement_len = (uint16_t)rec.replacement.size();
    uint64_t total = sizeof(info) + info.target_len + info.replacement_len;
    if (r.len > IJ2ART_RSP_DATA_MAX || total > IJ2ART_RSP_DATA_MAX - r.len) {
        r.flags |= 1;
        return false;
    }
    memcpy(r.data + r.len, &info, sizeof(info));
    memcpy(r.data + r.len + sizeof(info), rec.target.data(), info.target_len);
    memcpy(r.data + r.len + sizeof(info) + info.target_len,
           rec.replacement.data(), info.replacement_len);
    r.len += total;
    return true;
}

} // namespace ij2art
