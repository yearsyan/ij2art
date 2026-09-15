#pragma once
#include "../common/loader_proto.h"

// All management calls are serialized by the control-ring worker, which blocks
// all signals: uploaded constructors/destructors run on that thread.
bool ij2art_loader_command(const ij2art_cmd&, ij2art_rsp&);
void ij2art_loader_tick(); // expires abandoned UPLOADING records

// True when a LOADED record owns the module mapped at this base. A memfd-uploaded
// library has no live path, so dlopen(RTLD_NOLOAD) cannot re-reference it; the
// registry itself is the pin and UNLOAD refuses while an active hook uses it.
bool ij2art_loader_owns_base(uint64_t base);
