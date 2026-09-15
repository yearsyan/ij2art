// Self-hiding (shared by the carrier and the payload): unlink ourselves from r_map/solist
// and wipe the copies of our name string.
// Timing is critical: the linker heap (linker_alloc) is normally mprotected to r-- and is
// writable only during a dlopen flow, so this must be called from our own constructor. The
// writes use the pointer values already present in the chain, whose MTE tags are naturally
// correct.
#pragma once
#include <link.h>

struct ij2art_hide_result {
    link_map* lm;         // our own link_map (its position before unlinking), nullptr on failure
    struct r_debug* rd;   // the process _r_debug
};

ij2art_hide_result ij2art_hide_self();
