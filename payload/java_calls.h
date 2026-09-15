#pragma once
#include "../common/art_proto.h"

// Management-worker only. Execution and completion stay entirely in Java.
namespace ij2art::java_calls {
bool command(const ij2art_cmd& c, ij2art_rsp& r);
bool references(uint64_t dex_id, ij2art_rsp& r);
bool shutdown(ij2art_rsp& r);
void release();
}
