#pragma once
#include <jni.h>
#include "../common/art_proto.h"

// Called on an attached App thread AFTER runtime startup. The loader is retained.
// Without an App-delivered signal, the first JNI-dependent RPC lazily bootstraps
// readiness on the ring worker thread via public JNI APIs (attach + reflection);
// bootstrapping retries on later commands while the Application is not created.
extern "C" __attribute__((visibility("default")))
bool ij2art_runtime_ready(JNIEnv* env, jobject app_loader);

bool ij2art_art_command(const ij2art_cmd& command, ij2art_rsp& response);
void ij2art_art_tick();
bool ij2art_art_shutdown(ij2art_rsp& response);
