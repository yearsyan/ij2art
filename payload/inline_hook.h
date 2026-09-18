#pragma once
#include "../common/inline_proto.h"
#include "../common/probe_proto.h"

// All management calls are serialized by the control-ring worker. Hooked native
// functions execute concurrently. No ART state is touched by this backend.
bool ij2art_inline_command(const ij2art_cmd&, ij2art_rsp&);
bool ij2art_inline_can_shutdown(ij2art_rsp&);
bool ij2art_probe_command(const ij2art_cmd&, ij2art_rsp&);

// Internal process-lifetime hooks, serialized by the same worker. The caller
// owns stable original/stub storage and pins the code for the process lifetime.
// These are not user records: CLI DEL and shutdown must never remove them.
bool ij2art_inline_permanent(void* target, void* replacement, void** original,
                              void** stub, ij2art_rsp&);

// True while a hook or instruction probe may reference the module at this base.
// Includes limited probes and failed removals. The loader consults this before dlclose.
bool ij2art_inline_module_in_use(const void* base);
