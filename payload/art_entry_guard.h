#pragma once
#include <cstdint>
#include "../common/proto.h"
#include "art_profile.h"

namespace ij2art::entry_guard {
// Only after the exact libart build has been validated. No ART locks held.
bool install(uintptr_t art_base, const art_profile::Profile&, ij2art_rsp&);
bool ready();
size_t count();
// Infallible after admission, under exclusive mutator access. At most two
// methods per JNI slot; methods and entries must stay alive until process exit.
void protect(void* target, void* backup, const void* generic, const void* backup_code,
             const void* dispatch, bool native_target);
}
