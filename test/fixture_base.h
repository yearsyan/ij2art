// Shared harness for the fixture headers. Each fixture translation unit
// (test/art_jni.cpp, test/apk/jni/apkbridge.cpp) includes exactly one fixture
// header, so the file-scope state those headers declare cannot collide.
#pragma once
#include "art_fixture.h"
#include "../payload/art_admission.h"
#include <jni.h>
#include <cstdio>

namespace fixture_base {

using ij2art::admission::read;

inline JNIEnv* env(JavaVM* vm) {
    JNIEnv* result = nullptr;
    return vm && vm->GetEnv(reinterpret_cast<void**>(&result), JNI_VERSION_1_6) == JNI_OK ? result : nullptr;
}

// Describes and clears a pending JNI exception, mapping the call to a 0 result.
inline uint64_t checked(JNIEnv* e, uint64_t value) {
    if (!e->ExceptionCheck()) return value;
    e->ExceptionDescribe();
    e->ExceptionClear();
    return 0;
}

// artMethod address of one method, found by reflection through Executable.artMethod.
inline void* reflected_method(JNIEnv* e, jclass cls, const char* name, const char* sig, bool is_static) {
    jmethodID id = is_static ? e->GetStaticMethodID(cls, name, sig) : e->GetMethodID(cls, name, sig);
    if (!id) return nullptr;
    jobject reflected = e->ToReflectedMethod(cls, id, is_static);
    jclass executable = e->FindClass("java/lang/reflect/Executable");
    jfieldID field = e->GetFieldID(executable, "artMethod", "J");
    void* result = reinterpret_cast<void*>(e->GetLongField(reflected, field));
    e->DeleteLocalRef(executable);
    e->DeleteLocalRef(reflected);
    return result;
}

struct Core {
    JavaVM* vm{};
    jclass cases{};

    JNIEnv* env() { return fixture_base::env(vm); }

    void init(JNIEnv* e, const char* cases_class) {
        e->GetJavaVM(&vm);
        jclass local = e->FindClass(cases_class);
        if (local) { cases = static_cast<jclass>(e->NewGlobalRef(local)); e->DeleteLocalRef(local); }
    }
};

// Core plus build-bound libart symbol resolution and the GC/suspend scope the
// entry-point probes need. The Pause tag only shows up in ART traces.
struct ProfileCore : Core {
    uintptr_t base{};
    using Symbol = art_fixture::Symbol;

    const auto& profile() { return art_fixture::profile(base); }
    template<class Fn> Fn at(Symbol symbol) { return profile().at<Fn>(base, symbol); }

    void init(JNIEnv* e, uintptr_t art_base, const char* cases_class) {
        Core::init(e, cases_class);
        base = art_base;
    }

    struct Pause {
        ProfileCore& core;
        alignas(8) unsigned char gc[32]{};
        unsigned char suspended{};
        explicit Pause(ProfileCore& c, const char* tag) : core(c) {
            core.at<void(*)(void*, void*, int, int)>(Symbol::gc_enter)(
                gc, core.at<void*(*)()>(Symbol::current)(), 8, 9);
            core.at<void(*)(void*, const char*, bool)>(Symbol::suspend)(&suspended, tag, false);
        }
        ~Pause() {
            core.at<void(*)(void*)>(Symbol::resume)(&suspended);
            core.at<void(*)(void*)>(Symbol::gc_exit)(gc);
        }
        Pause(const Pause&) = delete;
        Pause& operator=(const Pause&) = delete;
    };
};

// Reflect N entries from cases.prepare() -- an array of Constructors or Methods,
// selected by prepare_sig -- into targets[i] via Executable.artMethod, and mirror
// the SDK's s%d statics into backups[i]. observe (optional) runs after each target
// capture; returning false fails the prepare. Returns 1, or 0 through checked().
template <int N, class Observe>
inline uint64_t prepare(JNIEnv* e, jclass cases, jclass sdk, const char* prepare_sig,
                        void** targets, void** backups, Observe observe) {
    jmethodID id = e->GetStaticMethodID(cases, "prepare", prepare_sig);
    if (!id) return checked(e, 0);
    auto array = static_cast<jobjectArray>(e->CallStaticObjectMethod(cases, id));
    if (!array) return checked(e, 0);
    jclass executable = e->FindClass("java/lang/reflect/Executable");
    jfieldID field = e->GetFieldID(executable, "artMethod", "J");
    for (int i = 0; i < N; ++i) {
        jobject target = e->GetObjectArrayElement(array, i);
        targets[i] = reinterpret_cast<void*>(e->GetLongField(target, field));
        if (!observe(e, i, targets[i])) return checked(e, 0);
        char name[8]; snprintf(name, sizeof(name), "s%d", i);
        jmethodID mid = e->GetStaticMethodID(sdk, name, "()V");
        jobject backup = mid ? e->ToReflectedMethod(sdk, mid, true) : nullptr;
        if (!backup) return checked(e, 0);
        backups[i] = reinterpret_cast<void*>(e->GetLongField(backup, field));
        e->DeleteLocalRef(target); e->DeleteLocalRef(backup);
    }
    e->DeleteLocalRef(array); e->DeleteLocalRef(executable);
    return checked(e, 1);
}

template <int N>
inline uint64_t prepare(JNIEnv* e, jclass cases, jclass sdk, const char* prepare_sig,
                        void** targets, void** backups) {
    return prepare<N>(e, cases, sdk, prepare_sig, targets, backups,
                      [](JNIEnv*, int, void*) { return true; });
}
}
