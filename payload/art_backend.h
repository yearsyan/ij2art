#pragma once
#include "art_profile.h"
#include "../common/proto.h"

namespace ij2art::art_backend {
struct Result {
    int status = 0;
    const char* reason = nullptr;
    bool retry = false;
    explicit operator bool() const { return status == 0; }
};
bool initialize(const art_profile::Profile&, uintptr_t base, const uint64_t* symbols,
                size_t symbol_count, ij2art_rsp&);
bool ready();
const art_profile::Profile* profile();
size_t guard_count();
// Publishes caller-owned immutable metadata BEFORE mutators resume. The publish
// callback must not allocate, call Java, or acquire ART locks.
Result install(void* target, void* backup, void* dispatch, void (*publish)(void*), void* context);
}
