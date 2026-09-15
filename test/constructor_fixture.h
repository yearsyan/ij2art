// Test-only private ABI probes, called after the build-bound HOOK_INIT.
#pragma once
#include "fixture_base.h"

namespace ctor_fixture {
using namespace ij2art::admission;
fixture_base::ProfileCore core;
void* targets[5]{};
void* backups[5]{};
using core_t = decltype(core);
using art_fixture::Symbol;
const auto& profile() { return core.profile(); }
template<class Fn> Fn at(Symbol symbol) { return core.at<Fn>(symbol); }
void init(JNIEnv* e, uintptr_t art_base) { core.init(e, art_base, "org/ij2art/test/ConstructorCases"); }
}
extern "C" JNIEXPORT uint64_t fixture_ctor_prepare(jclass sdk) {
    using namespace ctor_fixture;
    JNIEnv* e = core.env();
    if (!e || !core.base || !core.cases || !sdk) return 0;
    return fixture_base::prepare<5>(e, core.cases, sdk,
        "()[Ljava/lang/reflect/Constructor;", targets, backups);
}
extern "C" JNIEXPORT uint64_t fixture_ctor_run(uint64_t hooked) {
    using namespace ctor_fixture;
    JNIEnv* e = core.env();
    e->CallStaticVoidMethod(core.cases, e->GetStaticMethodID(core.cases, "run", "(Z)V"), hooked != 0);
    return fixture_base::checked(e, 1);
}
extern "C" JNIEXPORT uint64_t fixture_ctor_block(uint64_t action) {
    using namespace ctor_fixture;
    JNIEnv* e = core.env();
    jint state = e->CallStaticIntMethod(core.cases, e->GetStaticMethodID(core.cases, "block", "(I)I"), jint(action));
    return fixture_base::checked(e, state);
}
extern "C" JNIEXPORT uint64_t fixture_ctor_state(uint64_t index, uint64_t compile) {
    using namespace ctor_fixture;
    if (index >= 5 || !targets[index]) return UINT64_MAX;
    Api api; api.bind(core.base);
    void* self = at<void*(*)()>(Symbol::current)();
    void* cache = read<void*>(*api.runtime, profile().layout.runtime_cache);
    if (compile) {
        void* jit = read<void*>(*api.runtime, profile().layout.runtime_jit);
        void* pool = jit ? read<void*>(jit, 0x18) : nullptr;
        if (!pool) return UINT64_MAX;
        at<void(*)(void*, void*, void*, int)>(Symbol::add_compile_task)(pool, self, targets[index], 2);
    }
    core_t::Pause pause{core, "constructor fixture"};
    const void* quick = read<void*>(targets[index], 24);
    const void* oat = api.oat_code(targets[index], 8);
    uint64_t state = (oat ? 1 : 0) | (oat && oat == quick ? 2 : 0);
    if (cache) {
        api.lock(*api.jit_lock, self);
        api.lock_code(self);
        Api::for_codes(cache, [&](void* method, const void* code) {
            if (method == targets[index] && code == quick) state |= 4;
        });
        api.unlock_code(self);
        api.unlock(*api.jit_lock, self);
    }
    return state;
}
extern "C" JNIEXPORT uint64_t fixture_ctor_guards(uint64_t count) {
    using namespace ctor_fixture;
    if (count > 5) return 0;
    core_t::Pause pause{core, "constructor fixture"};
    void* runtime = *at<void**>(Symbol::runtime);
    void* instr = profile().instrumentation(runtime);
    for (unsigned i = 0; i < count; ++i) for (void* m : {targets[i], backups[i]}) {
        const void* expected = at<void*>(m == targets[i] ? Symbol::generic : Symbol::interpreter);
        const void* oat = at<const void*(*)(void*, size_t)>(Symbol::oat_code)(m, 8);
        if (at<const void*(*)(void*)>(Symbol::optimized)(m) != expected) return 10 + i;
        at<void(*)(void*, void*, const void*)>(Symbol::update_impl)(instr, m, oat ? oat : at<void*>(Symbol::nterp));
        if (read<const void*>(m, 24) != expected) return 20 + i;
        if (auto reset = at<void(*)(void*, void*)>(Symbol::reinitialize)) reset(instr, m);
        else at<void(*)(void*, void*, const void*)>(Symbol::initialize)(instr, m, expected);
        if (read<const void*>(m, 24) != expected) return 30 + i;
        at<void(*)(void*, void*)>(Symbol::stubs)(instr, m);
        if (read<const void*>(m, 24) != expected) return 40 + i;
    }
    return 1;
}
