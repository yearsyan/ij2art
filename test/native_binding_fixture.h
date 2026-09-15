// Build-bound JNI binding regression. Each runner uses a fresh fixture process.
#pragma once
#include "fixture_base.h"
#include <atomic>

namespace binding_fixture {
using ij2art::admission::read;
fixture_base::ProfileCore core;
jmethodID body;
void* targets[6]{};
void* backups[6]{};
void* dispatches[6]{};
void* managed_data;
void* control_target;
constexpr const char* names[] = {"instance", "statik", "syncInstance", "syncStatic", "missing", "control"};
using core_t = decltype(core);
using art_fixture::Symbol;
const auto& profile() { return core.profile(); }
template<class Fn> Fn at(Symbol symbol) { return core.at<Fn>(symbol); }
template<int Value, bool Sync> jint implementation(JNIEnv* e, jobject receiver, jint x) {
    return e->CallStaticIntMethod(core.cases, body, receiver, x, Value, Sync);
}
// Same vtable as this build's art::MethodCallback. Install through ART's real
// callback list, so both explicit registration and backup dlsym use the chain.
struct BindingCallback {
    std::atomic<unsigned> seen{0};
    virtual ~BindingCallback() = default;
    virtual void RegisterNativeMethod(void* method, const void*, void** result) {
        for (int i = 0; i < 5; ++i) {
            if (method == backups[i]) seen.fetch_or(0x100);
            if (method != targets[i]) continue;
            seen.fetch_or(1u << i);
            *result = i == 2 || i == 3 ? reinterpret_cast<void*>(implementation<900, true>)
                                      : reinterpret_cast<void*>(implementation<900, false>);
        }
        if (method == control_target) {
            seen.fetch_or(0x20);
            *result = reinterpret_cast<void*>(implementation<900, false>);
        }
    }
} callback;
bool callback_installed;
int bind(JNIEnv* e, int action) {
    if (action == 2) return e->UnregisterNatives(core.cases) == JNI_OK ? 1 : 0;
    JNINativeMethod methods[6];
    for (int i = 0; i < 6; ++i) {
        bool sync = i == 2 || i == 3;
        void* fn = action == 0
            ? (sync ? reinterpret_cast<void*>(implementation<7, true>) : reinterpret_cast<void*>(implementation<7, false>))
            : (sync ? reinterpret_cast<void*>(implementation<70, true>) : reinterpret_cast<void*>(implementation<70, false>));
        methods[i] = {const_cast<char*>(names[i]), const_cast<char*>("(I)I"), fn};
    }
    return e->RegisterNatives(core.cases, methods, 6) == JNI_OK ? 1 : 0;
}
void init(JNIEnv* e, uintptr_t art_base) {
    core.init(e, art_base, "org/ij2art/test/NativeBindingCases");
    if (core.cases) {
        body = e->GetStaticMethodID(core.cases, "nativeBody", "(Ljava/lang/Object;IIZ)I");
        if (body) bind(e, 0);
    }
}
}
// These symbols deliberately differ from the explicitly registered functions.
// There is NO exported symbol for missing(), so unregistration must throw there.
#define BINDING_EXPORT(Name, Sync) \
extern "C" JNIEXPORT jint JNICALL Java_org_ij2art_test_NativeBindingCases_##Name( \
    JNIEnv* e, jobject receiver, jint x) { return binding_fixture::implementation<700, Sync>(e, receiver, x); }
BINDING_EXPORT(instance, false)
BINDING_EXPORT(statik, false)
BINDING_EXPORT(syncInstance, true)
BINDING_EXPORT(syncStatic, true)
BINDING_EXPORT(control, false)
#undef BINDING_EXPORT
extern "C" JNIEXPORT jint JNICALL Java_org_ij2art_test_NativeBindingCases_00024Driver_bind(
    JNIEnv* e, jclass, jint action) { return binding_fixture::bind(e, action); }
extern "C" JNIEXPORT uint64_t fixture_binding_prepare(jclass sdk) {
    using namespace binding_fixture;
    JNIEnv* e = core.env();
    if (fixture_base::prepare<6>(e, core.cases, sdk,
            "()[Ljava/lang/reflect/Method;", targets, backups) != 1) return 0;
    managed_data = read<void*>(targets[5], 16);
    jobject control = e->ToReflectedMethod(core.cases, e->GetStaticMethodID(core.cases, "control", "(I)I"), true);
    jclass executable = e->FindClass("java/lang/reflect/Executable");
    jfieldID field = e->GetFieldID(executable, "artMethod", "J");
    control_target = reinterpret_cast<void*>(e->GetLongField(control, field));
    e->DeleteLocalRef(executable);
    e->DeleteLocalRef(control);
    return fixture_base::checked(e, 1);
}
extern "C" JNIEXPORT uint64_t fixture_binding_check(uint64_t remember) {
    using namespace binding_fixture;
    for (int i = 0; i < 6; ++i) {
        if (remember) dispatches[i] = read<void*>(targets[i], 16);
        if (read<void*>(targets[i], 16) != dispatches[i]) return 10 + i;
        if (read<void*>(targets[i], 24) != at<void*>(Symbol::generic)) return 20 + i;
        if (read<void*>(backups[i], 24) != at<void*>(i == 5 ? Symbol::interpreter : Symbol::generic)) return 30 + i;
        if (i < 5 && read<void*>(backups[i], 16) == dispatches[i]) return 40 + i;
    }
    return read<void*>(backups[5], 16) == managed_data ? 1 : 50;
}
extern "C" JNIEXPORT uint64_t fixture_binding_bind(uint64_t action) {
    using namespace binding_fixture;
    JNIEnv* e = core.env();
    return fixture_base::checked(e, bind(e, int(action)));
}
extern "C" JNIEXPORT uint64_t fixture_binding_callbacks(uint64_t action) {
    using namespace binding_fixture;
    if (action == 2) return callback.seen.load();
    core_t::Pause pause{core, "JNI binding fixture"};
    void* rt = *at<void**>(Symbol::runtime);
    void* callbacks = read<void*>(rt, profile().layout.runtime_callbacks);
    if ((action != 0) != callback_installed) {
        at<void(*)(void*, void*)>(action ? Symbol::add_method_callback : Symbol::remove_method_callback)(callbacks, &callback);
        callback_installed = action != 0;
    }
    callback.seen.store(0);
    return 1;
}
extern "C" JNIEXPORT uint64_t fixture_binding_run(uint64_t hooked, uint64_t value, uint64_t unbound) {
    using namespace binding_fixture;
    JNIEnv* e = core.env();
    e->CallStaticVoidMethod(core.cases, e->GetStaticMethodID(core.cases, "run", "(ZIZ)V"), hooked != 0, jint(value), unbound != 0);
    return fixture_base::checked(e, 1);
}
extern "C" JNIEXPORT uint64_t fixture_binding_race(uint64_t hooked) {
    using namespace binding_fixture;
    JNIEnv* e = core.env();
    e->CallStaticVoidMethod(core.cases, e->GetStaticMethodID(core.cases, "race", "(Z)V"), hooked != 0);
    return fixture_base::checked(e, 1);
}
extern "C" JNIEXPORT uint64_t fixture_binding_watch() {
    using namespace binding_fixture;
    JNIEnv* e = core.env();
    e->CallStaticVoidMethod(core.cases, e->GetStaticMethodID(core.cases, "watch", "()V"));
    return fixture_base::checked(e, 1);
}
