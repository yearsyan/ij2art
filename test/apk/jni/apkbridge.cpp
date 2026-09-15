// App-side readiness bridge for the real-APK verification (test/apk).
// Mirrors test/art_jni.cpp: dlopen the payload, hand over the App class
// loader, then start the control ring. The payload handle is never closed.
#include <jni.h>
#include <dlfcn.h>
#include "aot_fixture.h"
#include "../../constructor_fixture.h"
#include "../../synchronized_fixture.h"
#include "../../native_binding_fixture.h"
#include "../../hook_update_fixture.h"

static void boot(JNIEnv* env, jclass, jstring path, jobject loader) {
    const char* chars = env->GetStringUTFChars(path, nullptr);
    if (!chars) return;
    void* handle = dlopen(chars, RTLD_NOW | RTLD_LOCAL);
    env->ReleaseStringUTFChars(path, chars);
    jclass error = env->FindClass("java/lang/IllegalStateException");
    auto fail = [&](const char* text) {
        if (error) env->ThrowNew(error, text);
    };
    if (!handle) return fail(dlerror());
    auto ready = (bool (*)(JNIEnv*, jobject))dlsym(handle, "ij2art_runtime_ready");
    auto start = (void (*)())dlsym(handle, "ij2art_after_specialize");
    if (!ready || !start) return fail("payload exports missing");
    if (!ready(env, loader)) return fail("runtime readiness registration failed");
    start();
}

extern "C" JNIEXPORT void JNICALL
Java_org_ij2art_apktest_MainActivity_nativeStart(JNIEnv* env, jobject instance, jstring path,
                                                   jobject loader) {
    jclass cls = env->GetObjectClass(instance);
    aot_fixture::init(env, cls);
    ctor_fixture::init(env, aot_fixture::core.base);
    sync_fixture::init(env, aot_fixture::core.base);
    binding_fixture::init(env, aot_fixture::core.base);
    update_fixture::init(env);
    boot(env, cls, path, loader);
    env->DeleteLocalRef(cls);
}
