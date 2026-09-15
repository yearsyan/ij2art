// Boundary tests for common/hook_record.h: an exact fit, one byte short, several records
// accumulating, an oversized selector, and a tail canary. The old implementation checked the
// length of a single record only, so once 16 records had accumulated it wrote past the
// response slot -- this test reproduces the shape of review finding R4.
#include "../common/hook_record.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

using ij2art::HookRecordView;
using ij2art::append_hook_record;

namespace {
struct Guarded {
    ij2art_rsp r;
    uint8_t canary[128];
};

Guarded g;

void reset() {
    std::memset(&g, 0, sizeof(g.r));
    std::memset(g.canary, 0xa5, sizeof(g.canary));
}

void check_canary() {
    for (uint8_t b : g.canary) assert(b == 0xa5);
}

HookRecordView rec(uint64_t id, const std::string& t, const std::string& rep) {
    return HookRecordView{id, /*hits*/100 + id, /*last_hit_ms*/123456,
                          /*state*/2, /*in_flight*/1, t, rep};
}
} // namespace

int main() {
    // 1) Single-record round trip: the fields and strings come back byte-for-byte identical,
    // and len advances correctly.
    reset();
    {
        std::string t = "a.b.C.m(I)I", rep = "x.y.R.r(Lorg/ij2art/HookContext;)Ljava/lang/Object;";
        assert(append_hook_record(g.r, rec(7, t, rep)));
        assert(g.r.len == sizeof(ij2art_hook_info) + t.size() + rep.size());
        assert(g.r.flags == 0);
        ij2art_hook_info info{};
        std::memcpy(&info, g.r.data, sizeof(info));
        assert(info.id == 7 && info.hits == 107 && info.last_hit_ms == 123456);
        assert(info.state == 2 && info.in_flight == 1);
        assert(info.target_len == t.size() && info.replacement_len == rep.size());
        assert(std::memcmp(g.r.data + sizeof(info), t.data(), t.size()) == 0);
        assert(std::memcmp(g.r.data + sizeof(info) + t.size(), rep.data(), rep.size()) == 0);
        check_canary();
    }

    // 2) Exact fit: 72-byte records times 227 fill all 16344 bytes with not a single byte to
    // spare, and flags stays 0 the whole way.
    reset();
    {
        std::string t24(24, 't');
        for (int i = 0; i < 227; ++i) assert(append_hook_record(g.r, rec(i, t24, "")));
        assert(g.r.len == IJ2ART_RSP_DATA_MAX && g.r.flags == 0);
        assert(!append_hook_record(g.r, rec(227, t24, "")));  // buffer full: reject the write
        assert(g.r.flags == 1 && g.r.len == IJ2ART_RSP_DATA_MAX);
        check_canary();
    }

    // 3) One byte short: when the remaining space is total-1 the append must fail and write
    // nothing; afterwards, when the total equals the remaining space, it succeeds.
    reset();
    {
        std::string t24(24, 't'), t25(25, 'u');
        for (int i = 0; i < 226; ++i) assert(append_hook_record(g.r, rec(i, t24, "")));
        assert(g.r.len == 16272);
        assert(!append_hook_record(g.r, rec(226, t25, "")));  // needs 73 bytes, only 72 remain
        assert(g.r.flags == 1 && g.r.len == 16272);
        assert(append_hook_record(g.r, rec(226, t24, "")));   // 72 == remaining space, an exact fit
        assert(g.r.len == IJ2ART_RSP_DATA_MAX);
        check_canary();
    }

    // 4) The shape that reproduces R4: with 1031-byte records, the 16th overruns the buffer
    // after 15 have been stored; the append must now be rejected.
    reset();
    {
        std::string t(479, 'a'), rep(504, 'b');  // 48 + 983 = 1031 bytes per record
        for (int i = 0; i < 15; ++i) assert(append_hook_record(g.r, rec(i, t, rep)));
        assert(g.r.len == 15465 && g.r.flags == 0);
        assert(!append_hook_record(g.r, rec(15, t, rep)));
        assert(g.r.flags == 1 && g.r.len == 15465);
        check_canary();
    }

    // 5) The shape that matches the CLI limit: with two selectors of 1024 bytes each, seven
    // records fill the slot and the eighth is rejected.
    reset();
    {
        std::string t(1024, 'c'), rep(1024, 'd');  // 2096 bytes per record
        for (int i = 0; i < 7; ++i) assert(append_hook_record(g.r, rec(i, t, rep)));
        assert(g.r.len == 14672 && g.r.flags == 0);
        assert(!append_hook_record(g.r, rec(7, t, rep)));
        assert(g.r.flags == 1 && g.r.len == 14672);
        check_canary();
    }

    // 6) Defensive cases: an oversized selector (one that does not fit in a u16) and a corrupt
    // r.len are both recorded as truncation, and not a single byte is written.
    reset();
    {
        std::string huge(0x10000, 'e');
        assert(!append_hook_record(g.r, rec(1, huge, "")));
        assert(g.r.flags == 1 && g.r.len == 0);
        g.r.flags = 0;
        g.r.len = IJ2ART_RSP_DATA_MAX + 1000;  // must not write on upstream corruption
        assert(!append_hook_record(g.r, rec(2, "a", "")));
        assert(g.r.flags == 1 && g.r.len == IJ2ART_RSP_DATA_MAX + 1000);
        check_canary();
    }

    std::cout << "PASS: hook record bounds (exact fit, one byte short, cumulative, "
                 "oversized selector, canary)" << std::endl;
    return 0;
}
