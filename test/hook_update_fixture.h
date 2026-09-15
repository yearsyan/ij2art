#pragma once
#include "fixture_base.h"
#include <cstring>

namespace update_fixture {
fixture_base::Core core;
jmethodID body;
void* methods[8]{};
uint32_t flags[8]{};
void* entries[8][2]{};
jint native_value(JNIEnv* e, jobject, jint value) { return e->CallStaticIntMethod(core.cases, body, value); }
void init(JNIEnv* e) {
    core.init(e, "org/ij2art/test/HookUpdateCases");
    if (!core.cases) return;
    body = e->GetStaticMethodID(core.cases, "body", "(I)I");
    JNINativeMethod method{const_cast<char*>("nativeValue"), const_cast<char*>("(I)I"), reinterpret_cast<void*>(native_value)};
    if (body) e->RegisterNatives(core.cases, &method, 1);
}
}
extern "C" JNIEXPORT uint64_t fixture_update_prepare(jclass sdk) {
    using namespace update_fixture;
    JNIEnv* e = core.env();
    // Four targets plus four s%d backups share the methods[] array.
    return fixture_base::prepare<4>(e, core.cases, sdk,
        "()[Ljava/lang/reflect/Method;", methods, methods + 4);
}
extern "C" JNIEXPORT uint64_t fixture_update_metadata(uint64_t remember) {
    using namespace update_fixture;
    for (int i = 0; i < 8; ++i) {
        auto* bytes = static_cast<unsigned char*>(methods[i]);
        if (remember) { memcpy(&flags[i], bytes + 4, 4); memcpy(entries[i], bytes + 16, 16); }
        if (memcmp(&flags[i], bytes + 4, 4) || memcmp(entries[i], bytes + 16, 16)) return 10 + i;
    }
    return 1;
}
extern "C" JNIEXPORT uint64_t fixture_update_probe(uint64_t index, uint64_t x, uint64_t expected) {
    using namespace update_fixture;
    JNIEnv* e = core.env();
    e->CallStaticVoidMethod(core.cases, e->GetStaticMethodID(core.cases, "probe", "(III)V"), jint(index), jint(x), jint(expected));
    return fixture_base::checked(e, 1);
}
extern "C" JNIEXPORT uint64_t fixture_update_block(uint64_t action, uint64_t index) {
    using namespace update_fixture;
    JNIEnv* e = core.env();
    jint result = e->CallStaticIntMethod(core.cases, e->GetStaticMethodID(core.cases, "block", "(II)I"), jint(action), jint(index));
    return fixture_base::checked(e, result);
}
extern "C" JNIEXPORT uint64_t fixture_update_race(uint64_t start) {
    using namespace update_fixture;
    JNIEnv* e = core.env();
    e->CallStaticVoidMethod(core.cases, e->GetStaticMethodID(core.cases, "race", "(Z)V"), start != 0);
    return fixture_base::checked(e, 1);
}
