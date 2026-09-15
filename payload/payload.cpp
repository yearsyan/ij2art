// The payload is loaded before the domain switch, and the control ring is created only after
// the switch has succeeded. The linker metadata is left intact.
#include <android/log.h>
#include <stdlib.h>
#include <unistd.h>
#include "ring.h"

extern "C" __attribute__((visibility("default")))
void ij2art_after_specialize() {
    __android_log_print(ANDROID_LOG_INFO, "ij2art", "control ring: %s",
                        ij2art_ring_start() ? "starting" : "FAILED");
}

__attribute__((constructor)) static void payload_init() {
    const char* pkg = getenv("ij2art_pkg");
    __android_log_print(ANDROID_LOG_INFO, "ij2art", "payload loaded: pkg=%s pid=%d uid=%d",
                        pkg ? pkg : "?", getpid(), getuid());
    // The carrier is responsible for cleaning up the environment value. No threads may be
    // started here, and we must not unlink or wipe any linker data.
}
