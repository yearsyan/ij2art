// Fixture-only private ABI probes. Invoked only after HOOK_INIT has validated
// libart's build. Never linked into the payload or exported by production code.
#pragma once
#include "../../fixture_base.h"
#include <atomic>
#include <link.h>
#include <unistd.h>

namespace aot_fixture {
using ij2art::admission::read;
fixture_base::ProfileCore core;
jclass owner;
void* methods[7]{}; // add, greet, instanceScale, blocked, natMul, natInstanceScale, control
void* backups[6]{};
std::atomic<int> watch{0};
std::atomic<bool> held{false}, release{false};
using core_t = decltype(core);
using art_fixture::Symbol;
const auto& profile() { return core.profile(); }
template<class Fn> Fn api(Symbol symbol) { return core.at<Fn>(symbol); }
JNIEnv* env() { return core.env(); }
void* method(JNIEnv* e, jclass cls, const char* name, const char* sig, bool is_static) {
    return fixture_base::reflected_method(e, cls, name, sig, is_static);
}
void init(JNIEnv* e, jclass cls) {
    e->GetJavaVM(&core.vm);
    owner = static_cast<jclass>(e->NewGlobalRef(cls));
    methods[0] = method(e, cls, "add", "(II)I", true);
    methods[1] = method(e, cls, "greet", "(Ljava/lang/String;I)Ljava/lang/String;", true);
    methods[2] = method(e, cls, "instanceScale", "(I)I", false);
    methods[3] = method(e, cls, "blocked", "(I)I", true);
    methods[4] = method(e, cls, "natMul", "(II)I", true);
    methods[5] = method(e, cls, "natInstanceScale", "(I)I", false);
    methods[6] = method(e, cls, "control", "(I)I", true);
    // libart cannot be dlopen'ed from an ordinary App's linker namespace.
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void*) {
        if (!strstr(info->dlpi_name, "/libart.so")) return 0;
        core.base = info->dlpi_addr;
        return 1;
    }, nullptr);
}
const void* quick(void* m) { return read<const void*>(m, 24); }
uint64_t exercise(int count) {
    if (!core.base || count < 1 || count > 6) return 2;
    core_t::Pause pause{core, "aot fixture"};
    void* runtime = *api<void**>(Symbol::runtime);
    void* instr = profile().instrumentation(runtime);
    using Write = void(*)(void*, const void*);
    using WriteMember = void(*)(void*, void*, const void*);
    using Reset = void(*)(void*, void*);
    for (int i = 0; i < count; ++i) {
        // Native-hook backups (index >= 4) keep the generic JNI entry.
        bool native_hook = i >= 4;
        for (void* m : {methods[i], backups[i]}) {
            const void* expected = api<void*>(m == methods[i] || native_hook ? Symbol::generic : Symbol::interpreter);
            if (quick(m) != expected) return 100 + i;
            const void* oat = api<const void*(*)(void*, size_t)>(Symbol::oat_code)(m, 8);
            const void* requested = oat ? oat : api<void*>(Symbol::nterp);
            if (api<const void*(*)(void*)>(Symbol::optimized)(m) != expected) return 200 + i;
            if (api<const void*(*)(void*, void*)>(Symbol::invoke)(instr, m) != expected) return 300 + i;
            if (auto select = api<const void*(*)(void*, void*)>(Symbol::maybe_invoke))
                if (select(instr, m) != expected) return 400 + i;
            if (auto update = api<Write>(Symbol::update)) update(m, requested);
            else api<WriteMember>(Symbol::initialize)(instr, m, requested);
            if (quick(m) != expected) return 500 + i;
            for (Symbol offset : {Symbol::update_impl, Symbol::outer_update, Symbol::native_update}) {
                if (auto writer = api<WriteMember>(offset)) writer(instr, m, requested);
                if (quick(m) != expected) return 600 + i;
            }
            for (Symbol offset : {Symbol::reinitialize, Symbol::stubs}) {
                if (auto reset = api<Reset>(offset)) reset(instr, m);
                if (quick(m) != expected) return 700 + i;
            }
            // Raw OAT lookup still returns the old code for both roles.
            if (api<const void*(*)(void*, size_t)>(Symbol::oat_code)(m, 8) != oat) return 800 + i;
        }
    }
    void* control = methods[6];
    const void* before = quick(control);
    const void* interp = api<void*>(Symbol::interpreter);
    if (auto update = api<Write>(Symbol::update)) update(control, interp);
    else api<WriteMember>(Symbol::update_impl)(instr, control, interp);
    if (quick(control) != interp) return 900;
    api<WriteMember>(Symbol::update_impl)(instr, control, before);
    if (quick(control) != before) return 901;
    return 1;
}
}

extern "C" JNIEXPORT uint64_t fixture_capture_backup(jclass cls) {
    using namespace aot_fixture;
    JNIEnv* e = env();
    if (!e || !cls) return 0;
    for (int i = 0; i < 6; ++i) {
        char name[8]; snprintf(name, sizeof(name), "s%d", i);
        backups[i] = method(e, cls, name, "()V", true);
        if (!backups[i] || e->ExceptionCheck()) return 0;
    }
    return 1;
}
extern "C" JNIEXPORT uint64_t fixture_native_state(uint64_t which) {
    using namespace aot_fixture;
    if (!core.base) return UINT64_MAX;
    void* m = which < 2 ? methods[4] : methods[5];  // natMul, natInstanceScale
    core_t::Pause pause{core, "aot fixture"};
    switch (which & 1) {
    case 0: return uint64_t(quick(m));
    default: return uint64_t(read<void*>(m, 16));  // data_: JNI fn or dlsym stub
    }
}
extern "C" JNIEXPORT uint64_t fixture_aot_state() {
    using namespace aot_fixture;
    if (!core.base) return UINT64_MAX;
    core_t::Pause pause{core, "aot fixture"};
    uint64_t result = 0;
    // Managed targets + control; declared natives never have OAT code.
    const int ids[] = {0, 1, 2, 3, 6};
    for (int k = 0; k < 5; ++k) {
        const void* oat = api<const void*(*)(void*, size_t)>(Symbol::oat_code)(methods[ids[k]], 8);
        if (oat) result |= 1ull << k;
        if (oat && oat == quick(methods[ids[k]])) result |= 1ull << (k + 8);
    }
    return result;
}
extern "C" JNIEXPORT uint64_t fixture_guard_exercise(uint64_t count) { return aot_fixture::exercise(count); }
extern "C" JNIEXPORT uint64_t fixture_guard_watch(uint64_t count) { aot_fixture::watch.store(count); return 1; }
extern "C" JNIEXPORT uint64_t fixture_block(uint64_t action) {
    using namespace aot_fixture;
    if (action == 0) {
        JNIEnv* e = env();
        e->CallStaticVoidMethod(owner, e->GetStaticMethodID(owner, "startBlock", "()V"));
        if (e->ExceptionCheck()) return 0;
    } else if (action == 1) release.store(true);
    return held.load();
}
extern "C" JNIEXPORT uint64_t fixture_block_fingerprint() {
    using namespace aot_fixture;
    core_t::Pause pause{core, "aot fixture"};
    return read<uint32_t>(methods[3], 4) ^ read<uint64_t>(methods[3], 16) ^ read<uint64_t>(methods[3], 24);
}
extern "C" JNIEXPORT void JNICALL Java_org_ij2art_apktest_MainActivity_nativeHold(JNIEnv*, jclass) {
    aot_fixture::held.store(true);
    while (!aot_fixture::release.load()) usleep(10000);
    aot_fixture::held.store(false);
}
extern "C" JNIEXPORT jlong JNICALL Java_org_ij2art_apktest_MainActivity_nativeCheck(JNIEnv*, jclass) {
    int count = aot_fixture::watch.load();
    return count ? aot_fixture::exercise(count) : 0;
}
extern "C" JNIEXPORT jint JNICALL Java_org_ij2art_apktest_MainActivity_natMul(JNIEnv*, jclass, jint a, jint b) {
    return a * b + 1;
}
extern "C" JNIEXPORT jint JNICALL Java_org_ij2art_apktest_MainActivity_natInstanceScale(JNIEnv*, jobject, jint v) {
    return v * 5 + 2;
}
