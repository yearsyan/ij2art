// Internal interface between art.cpp and replace.cpp. Both sides are called only from the
// control worker.
#pragma once
#include <jni.h>
#include <cstdint>
#include <string>
#include "../common/art_proto.h"
#include "dex_store.h"

namespace ij2art::artint {

int message(ij2art_rsp& r, int error, const std::string& text);
int java_error(JNIEnv* env, ij2art_rsp& r, const char* operation, int code = IJ2ART_E_JAVA);
bool attach(ij2art_rsp& r);          // worker_env() is usable after success
JNIEnv* worker_env();
jobject app_loader();                  // App-explicitly-registered ClassLoader (global ref)
bool ensure_sdk(JNIEnv* env, ij2art_rsp& r);
DexStore& dex_store();
jobject dex_loader_for(uint64_t id);   // only for a dex that is READY and already has a loader
void dex_ref_hooks(uint64_t id, int delta);
std::string libart_build_id();

// SDK shared objects (valid after ensure_sdk; not freed while the backend exists)
jclass sdk_bridge();                   // org.ij2art.Bridge (global ref)
jclass sdk_backup();                   // org.ij2art.Backup (global ref)
jobject sdk_class_loader();            // SDK InMemoryDexClassLoader, parent=App loader

} // namespace ij2art::artint

// Backend entry points provided by replace.cpp; art.cpp routes to them.
namespace ij2art::replace {

bool init(const ij2art_cmd& c, ij2art_rsp& r);     // HOOK_INIT
void add(const ij2art_cmd& c, ij2art_rsp& r);      // HOOK_ADD
void update(const ij2art_cmd& c, ij2art_rsp& r);   // HOOK_UPDATE
void collect();                                    // retired replacement roots, worker only
void del(const ij2art_cmd& c, ij2art_rsp& r);      // HOOK_DEL
void query(const ij2art_cmd& c, ij2art_rsp& r);    // HOOK_QUERY
void list(ij2art_rsp& r);                            // HOOK_LIST
// Close replacement admission permanently. This is NOT physical unhook/unload.
// retain_sdk=true preserves all roots/DEX accounting for permanent JNI forwarding.
// false means accepted replacements are still running; retry without admitting installs.
bool shutdown_all(bool& retain_sdk);
bool available();                                      // is there a safely installable adapter?

} // namespace ij2art::replace
