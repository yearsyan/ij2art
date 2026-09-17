// Entry point that starts the control ring (called from the payload.cpp constructor).
#pragma once

#ifdef __cplusplus
extern "C"
#endif
bool ij2art_ring_start();

// The control worker's disguise name. One string for two callers that must agree byte for
// byte: ring.cpp sets it as the worker's comm, and art.cpp passes it as the JNI attach name —
// ART's CreatePeer renames the TID from JavaVMAttachArgs.name, so a divergent attach name
// would overwrite the comm-level disguise with a plaintext tag.
#ifdef __cplusplus
extern "C"
#endif
const char* ij2art_ring_worker_name();
