#include "../payload/jni_abi.h"
#include <jni.h>
#include <array>
#include <cstring>

using namespace ij2art;
namespace {
struct Entry { const char* name; const char* descriptor; unsigned slot; };
const Entry entries[] = {
    {"mixed", "(ZBCSIJFDLjava/lang/Object;FIDFDFDD[Ljava/lang/Object;FJI)[Ljava/lang/Object;", 0},
    {"instance", "(Ljava/lang/Object;DI)[Ljava/lang/Object;", 1},
    {"z", "(Z)Z", 2}, {"b", "(B)B", 3}, {"c", "(C)C", 4}, {"s", "(S)S", 5},
    {"i", "(I)I", 6}, {"j", "(J)J", 7}, {"f", "(F)F", 8}, {"d", "(D)D", 9},
    {"l", "(Ljava/lang/Object;)Ljava/lang/Object;", 10}, {"v", "()V", 11},
    {"thrown", "()V", 12}, {"pointers", "()[J", 13}, {"last", "(I)I", 127}
};
std::array<JniLayout, IJ2ART_JNI_SLOTS> plans;

jobject box(JNIEnv* env, char kind, uint64_t bits) {
    if (kind == 'L') return reinterpret_cast<jobject>(bits);
    const char* types = "ZBCSIJFD";
    const char* names[] = {"java/lang/Boolean", "java/lang/Byte", "java/lang/Character", "java/lang/Short",
                          "java/lang/Integer", "java/lang/Long", "java/lang/Float", "java/lang/Double"};
    const char* descriptors[] = {"(Z)Ljava/lang/Boolean;", "(B)Ljava/lang/Byte;", "(C)Ljava/lang/Character;",
        "(S)Ljava/lang/Short;", "(I)Ljava/lang/Integer;", "(J)Ljava/lang/Long;", "(F)Ljava/lang/Float;", "(D)Ljava/lang/Double;"};
    size_t at = std::strchr(types, kind) - types;
    jclass cls = env->FindClass(names[at]);
    if (!cls) return nullptr;
    jmethodID factory = env->GetStaticMethodID(cls, "valueOf", descriptors[at]);
    if (!factory) return nullptr;
    jvalue value{};
    static_assert(sizeof(value) == sizeof(bits));
    std::memcpy(&value, &bits, sizeof(value));
    jobject result = env->CallStaticObjectMethodA(cls, factory, &value);
    env->DeleteLocalRef(cls);
    return result;
}
}

extern "C" JniResult ij2art_jni_dispatch(uint64_t slot, const JniCapture* saved, const void* stack) {
    JNIEnv* env = reinterpret_cast<JNIEnv*>(saved->gp[0]);
    auto& layout = plans.at(slot);
    if (slot == 12) {
        jclass error = env->FindClass("java/lang/IllegalStateException");
        if (error) env->ThrowNew(error, "static JNI exception");
        return {0, JniReturn::GP};
    }
    if (slot == 13) {
        jlong pointers[IJ2ART_JNI_SLOTS];
        for (unsigned i = 0; i < IJ2ART_JNI_SLOTS; ++i)
            pointers[i] = reinterpret_cast<jlong>(ij2art_jni_slots[i]);
        auto result = env->NewLongArray(IJ2ART_JNI_SLOTS);
        if (result) env->SetLongArrayRegion(result, 0, IJ2ART_JNI_SLOTS, pointers);
        return {reinterpret_cast<uint64_t>(result), JniReturn::Reference};
    }
    if (slot <= 1) {
        if (env->PushLocalFrame(128) != JNI_OK) return {0, JniReturn::Reference};
        jclass object = env->FindClass("java/lang/Object");
        auto result = object ? env->NewObjectArray(layout.arguments.size() + slot, object, nullptr) : nullptr;
        if (result && slot) env->SetObjectArrayElement(result, 0, reinterpret_cast<jobject>(saved->gp[1]));
        for (size_t i = 0; result && i < layout.arguments.size() && !env->ExceptionCheck(); ++i) {
            const auto& arg = layout.arguments[i];
            jobject value = box(env, arg.type, jni_argument_bits(arg, *saved, stack));
            if (!env->ExceptionCheck()) env->SetObjectArrayElement(result, i + slot, value);
        }
        // Exercise JNI calls/allocations while the original register/stack handles
        // are live. This is not a claim that a moving collection happened.
        result = static_cast<jobjectArray>(env->PopLocalFrame(result));
        return {reinterpret_cast<uint64_t>(result), JniReturn::Reference};
    }
    uint64_t bits = layout.arguments.empty() ? 0 : jni_argument_bits(layout.arguments[0], *saved, stack);
    JniReturn kind = layout.result == 'F' ? JniReturn::Float : layout.result == 'D' ? JniReturn::Double :
                     layout.result == 'L' ? JniReturn::Reference : JniReturn::GP;
    return {bits, kind};
}

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = env->FindClass("org/ij2art/test/JniAbi");
    if (!cls) return JNI_ERR;
    for (const auto& entry : entries) {
        std::string error;
        if (!jni_layout(entry.descriptor, plans[entry.slot], error)) return JNI_ERR;
        JNINativeMethod native{const_cast<char*>(entry.name), const_cast<char*>(entry.descriptor),
                               ij2art_jni_slots[entry.slot]};
        if (env->RegisterNatives(cls, &native, 1) != JNI_OK) return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
