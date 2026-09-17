#include <jni.h>
#include <dlfcn.h>

static void start_payload(JNIEnv* env, jstring path, jobject loader) {
    const char* chars = env->GetStringUTFChars(path, nullptr);
    if (!chars) return;
    void* handle = dlopen(chars, RTLD_NOW | RTLD_LOCAL);
    env->ReleaseStringUTFChars(path, chars);
    auto error = [&](const char* text) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls) env->ThrowNew(cls, text);
    };
    if (!handle) { error(dlerror()); return; }
    auto ready = (bool(*)(JNIEnv*, jobject))dlsym(handle, "ij2art_runtime_ready");
    auto start = (void(*)())dlsym(handle, "ij2art_after_specialize");
    if (!ready || !start || !ready(env, loader)) { error("runtime readiness registration failed"); return; }
    start();
    // The payload exports registered JNI functions: retain the dlopen handle for this process.
}

extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_Main_start(
        JNIEnv* env, jclass, jstring path, jobject loader) {
    start_payload(env, path, loader);
}

extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_JavaCallMain_start(
        JNIEnv* env, jclass, jstring path, jobject loader) {
    start_payload(env, path, loader);
}

extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_HookMain_start(
        JNIEnv* env, jclass, jstring path, jobject loader) {
    start_payload(env, path, loader);
}

extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_AdmissionMain_start(
        JNIEnv* env, jclass, jstring path, jobject loader) {
    start_payload(env, path, loader);
}

// Fixture-only JIT task. It holds an actual pool worker outside runnable state,
// reproducing the part of compilation that STW alone cannot exclude.
#include "../payload/art_admission.h"
#include "art_fixture.h"
using art_fixture::Symbol;
#include <atomic>
#include <link.h>
#include <unistd.h>
namespace {
struct BusyJitTask {
    std::atomic<bool> entered{false}, release{false}, done{false};
    virtual ~BusyJitTask() = default;
    virtual void Run(void*) {
        entered.store(true);
        for (int i = 0; i < 12000 && !release.load(); ++i) usleep(10000);
    }
    virtual void Finalize() { done.store(true); }
} busy_jit_task;
}
static uintptr_t libart_base() {
    uintptr_t base = 0;
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* out) {
        if (!strstr(info->dlpi_name, "/libart.so")) return 0;
        if (ij2art::art_profile::from_base(info->dlpi_addr))
            *static_cast<uintptr_t*>(out) = info->dlpi_addr;
        return 1;
    }, &base);
    return base;
}
extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_AdmissionMain_holdJit(
        JNIEnv* env, jclass) {
    uintptr_t base = libart_base();
    if (!base) {
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), "fixture ART ABI mismatch");
        return;
    }
    auto current = art_fixture::at<void*(*)()>(base, Symbol::current);
    ij2art::admission::Api api;
    api.bind(base);
    void* jit = ij2art::admission::read<void*>(*api.runtime, api.profile->layout.runtime_jit);
    void* pool = jit ? ij2art::admission::read<void*>(jit, 0x18) : nullptr;
    if (!pool) {
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), "fixture requires JIT pool");
        return;
    }
    auto enqueue = art_fixture::at<void(*)(void*, void*, BusyJitTask*)>(base, Symbol::add_generic_task);
    enqueue(pool, current(), &busy_jit_task);
    for (int i = 0; i < 1000 && !busy_jit_task.entered.load(); ++i) usleep(10000);
    if (!busy_jit_task.entered.load())
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), "JIT task did not start");
}
extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_AdmissionMain_releaseJit(
        JNIEnv* env, jclass) {
    busy_jit_task.release.store(true);
    for (int i = 0; i < 1000 && !busy_jit_task.done.load(); ++i) usleep(10000);
    if (!busy_jit_task.done.load())
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), "JIT task did not finish");
}

// Verify actual ART code-cache state, not a timing assumption based on warmup.
extern "C" JNIEXPORT jlong JNICALL Java_org_ij2art_test_AdmissionMain_codeState(
        JNIEnv* env, jclass, jobject reflected, jint compile_kind) {
    using namespace ij2art::admission;
    uintptr_t base = libart_base();
    if (!base) return -1;
    Api api; api.bind(base);
    auto current = art_fixture::at<void*(*)()>(base, Symbol::current);
    void* self = current();
    jclass cls = env->FindClass("java/lang/reflect/Executable");
    jfieldID field = env->GetFieldID(cls, "artMethod", "J");
    void* method = reinterpret_cast<void*>(env->GetLongField(reflected, field));
    if (env->ExceptionCheck()) return -1;
    void* jit = read<void*>(*api.runtime, api.profile->layout.runtime_jit);
    void* cache = read<void*>(*api.runtime, api.profile->layout.runtime_cache);
    if (!cache) return 0;
    if (compile_kind >= 0) {
        api.prepare(self);
        void* pool = jit ? read<void*>(jit, 0x18) : nullptr;
        if (!pool) return -1;
        auto enqueue = art_fixture::at<void(*)(void*, void*, void*, int)>(base, Symbol::add_compile_task);
        if (compile_kind > 2) return -1;
        enqueue(pool, self, method, api.profile->compilation_kinds[compile_kind]);
    }
    uint64_t count = 0, deps = 0;
    if (compile_kind == -2) {
        // Seed real ART bookkeeping deterministically: OEM compiler choices do
        // not guarantee a CHA dependency, nor a zombie surviving the next GC.
        api.lock(*api.jit_lock, self);
        api.lock_code(self);
        const void* quick = read<const void*>(method, 24);
        if (api.erase_pointer_set) Api::for_codes(cache, [&](void* owner, const void* code) {
            if (owner != method || code == quick) return;
            api.erase_pointer_set(Api::bytes(cache, api.profile->layout.cache_zombies), &code);
            art_fixture::insert_code(base, Api::bytes(cache, api.profile->layout.cache_osr_zombies), code);
        });
        api.unlock_code(self);
        api.lock(*api.cha_lock, self);
        void* cha = read<void*>(read<void*>(*api.runtime, api.profile->layout.runtime_linker), api.profile->layout.linker_cha);
        art_fixture::add_dependency(base, cha, method, static_cast<const unsigned char*>(quick) - 4);
        api.unlock(*api.cha_lock, self);
        api.unlock(*api.jit_lock, self);
    }
    api.lock(*api.jit_lock, self);
    api.lock_code(self);
    Api::for_codes(cache, [&](void* owner, const void*) { if (owner == method) ++count; });
    api.unlock_code(self);
    api.unlock(*api.jit_lock, self);
    auto osr = art_fixture::at<void*(*)(void*, void*)>(base, Symbol::lookup_osr);
    bool has_osr = osr(cache, method) != nullptr;
    api.lock(*api.cha_lock, self);
    void* cha = read<void*>(read<void*>(*api.runtime, api.profile->layout.runtime_linker), api.profile->layout.linker_cha);
    for (void* node = read<void*>(cha, 0x10); node; node = read<void*>(node, 0)) {
        auto* end = read<unsigned char*>(node, 0x20);
        for (auto* pair = read<unsigned char*>(node, 0x18); pair != end; pair += 16)
            if (read<void*>(pair, 0) == method) ++deps;
    }
    api.unlock(*api.cha_lock, self);
    bool pattern = api.profile->is_pattern(base, read<const void*>(method, 24));
    return count | (uint64_t(has_osr) << 16) | (uint64_t(pattern) << 17) | (deps << 32);
}
extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_AdmissionMain_collectCode(
        JNIEnv*, jclass) {
    uintptr_t base = libart_base();
    if (!base) return;
    ij2art::admission::Api api; api.bind(base);
    void* cache = ij2art::admission::read<void*>(*api.runtime, api.profile->layout.runtime_cache);
    if (cache) {
        auto current = art_fixture::at<void*(*)()>(base, Symbol::current);
        auto collect = art_fixture::at<void(*)(void*, void*)>(base, Symbol::collect_cache);
        collect(cache, current());
    }
}
extern "C" JNIEXPORT jint JNICALL Java_org_ij2art_test_AdmissionMain_runtimeMode(
        JNIEnv*, jclass) {
    uintptr_t base = libart_base();
    if (!base) return -1;
    ij2art::admission::Api api; api.bind(base);
    using ij2art::admission::read;
    void* jit = read<void*>(*api.runtime, api.profile->layout.runtime_jit);
    return (jit && read<uint8_t>(read<void*>(jit, 0x10), 0) ? 1 : 0) |
        (read<uint32_t>(*api.runtime, api.profile->layout.runtime_debuggable) != 0 ? 2 : 0);
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_ij2art_test_AdmissionMain_hasPatternStubs(
        JNIEnv*, jclass) {
    return art_fixture::profile(libart_base()).pattern_count != 0;
}

extern "C" JNIEXPORT jboolean JNICALL Java_org_ij2art_test_AdmissionMain_opaqueIds(
        JNIEnv* env, jclass cls) {
    return (reinterpret_cast<uintptr_t>(env->GetStaticMethodID(cls, "cold", "(I)I")) & 1) != 0;
}

extern "C" JNIEXPORT jint JNICALL Java_org_ij2art_test_AdmissionMain_processId(
        JNIEnv*, jclass) { return getpid(); }

#include <cstring>
#include "constructor_fixture.h"
#include "synchronized_fixture.h"
#include "native_binding_fixture.h"
#include "hook_update_fixture.h"
// One bootstrap for all four Hook fixtures; the tag picks the fixture side and is
// mirrored back to the runner as the READY prefix (see FixtureMain.java).
extern "C" JNIEXPORT void JNICALL Java_org_ij2art_test_FixtureMain_start(
        JNIEnv* env, jclass, jstring path, jobject loader, jstring fixture) {
    const char* which = env->GetStringUTFChars(fixture, nullptr);
    if (!which) return;
    bool known = true;
    if (strcmp(which, "ctor") == 0) ctor_fixture::init(env, libart_base());
    else if (strcmp(which, "sync") == 0) sync_fixture::init(env, libart_base());
    else if (strcmp(which, "binding") == 0) binding_fixture::init(env, libart_base());
    else if (strcmp(which, "update") == 0) update_fixture::init(env);
    else known = false;
    env->ReleaseStringUTFChars(fixture, which);
    if (!known) {
        jclass cls = env->FindClass("java/lang/IllegalStateException");
        if (cls) env->ThrowNew(cls, "unknown fixture tag");
        return;
    }
    start_payload(env, path, loader);
}
extern "C" JNIEXPORT jint JNICALL Java_org_ij2art_test_FixtureMain_processId(
        JNIEnv*, jclass) { return getpid(); }
