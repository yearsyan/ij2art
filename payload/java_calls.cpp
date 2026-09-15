#include "java_calls.h"
#include "art_internal.h"
#include "../common/java_proto.h"

namespace ij2art::java_calls {
namespace {
jclass runner;
jmethodID submit_id, query_id, list_id, drop_id, refs_id, close_id;
bool closing;

bool ensure(JNIEnv* env, ij2art_rsp& r) {
    if (runner) return true;
    if (!artint::ensure_sdk(env, r)) return false;
    jclass loader_class = env->FindClass("java/lang/ClassLoader");
    jmethodID load = loader_class ? env->GetMethodID(loader_class, "loadClass",
        "(Ljava/lang/String;)Ljava/lang/Class;") : nullptr;
    jstring name = load ? env->NewStringUTF("org.ij2art.JavaCalls") : nullptr;
    auto cls = name ? static_cast<jclass>(env->CallObjectMethod(artint::sdk_class_loader(), load, name)) : nullptr;
    if (!cls || env->ExceptionCheck()) {
        artint::java_error(env, r, "load Java method executor"); return false;
    }
    // Stop at the first pending exception: CheckJNI forbids further lookups.
    submit_id = query_id = list_id = drop_id = refs_id = close_id = nullptr;
    submit_id = env->GetStaticMethodID(cls, "submit", "(Ljava/lang/ClassLoader;J[BZ)J");
    if (submit_id) query_id = env->GetStaticMethodID(cls, "query", "(J)[B");
    if (query_id) list_id = env->GetStaticMethodID(cls, "list", "()[B");
    if (list_id) drop_id = env->GetStaticMethodID(cls, "drop", "(J)[B");
    if (drop_id) refs_id = env->GetStaticMethodID(cls, "references", "(J)Z");
    if (refs_id) close_id = env->GetStaticMethodID(cls, "close", "()Z");
    if (close_id) runner = static_cast<jclass>(env->NewGlobalRef(cls));
    if (!runner || env->ExceptionCheck()) {
        artint::java_error(env, r, "resolve Java executor ABI"); return false;
    }
    return true;
}

void response(JNIEnv* env, jbyteArray bytes, ij2art_rsp& r) {
    if (!bytes || env->ExceptionCheck()) { artint::java_error(env, r, "Java executor"); return; }
    jsize size = env->GetArrayLength(bytes);
    if (size < 0 || size > IJ2ART_RSP_DATA_MAX) {
        artint::message(r, IJ2ART_E_LIMIT, "Java result exceeds response slot; query java list for job identity");
        return;
    }
    env->GetByteArrayRegion(bytes, 0, size, reinterpret_cast<jbyte*>(r.data));
    if (env->ExceptionCheck()) { artint::java_error(env, r, "copy Java result"); return; }
    r.len = size;
}
}

bool command(const ij2art_cmd& c, ij2art_rsp& r) {
    if (c.type < IJ2ART_CMD_JAVA_CALL || c.type > IJ2ART_CMD_JAVA_DROP) return false;
    if (c.type == IJ2ART_CMD_JAVA_CALL && closing) {
        artint::message(r, IJ2ART_E_STATE, "Java executor is closing"); return true;
    }
    if (c.type == IJ2ART_CMD_JAVA_CALL &&
        (!c.len || c.len > IJ2ART_CMD_DATA_MAX || c.args[0] > 1)) {
        artint::message(r, IJ2ART_E_INVALID, "java call requires JSON <=3992 bytes and thread=main/new");
        return true;
    }
    if (!artint::attach(r)) return true;
    JNIEnv* env = artint::worker_env();
    if (env->PushLocalFrame(32) != JNI_OK) {
        artint::java_error(env, r, "Java executor local frame"); return true;
    }
    if (!ensure(env, r)) { env->PopLocalFrame(nullptr); return true; }
    jbyteArray result = nullptr;
    if (c.type == IJ2ART_CMD_JAVA_CALL) {
        jobject loader = c.addr ? artint::dex_loader_for(c.addr) : artint::sdk_class_loader();
        if (!loader) artint::message(r, IJ2ART_E_NOT_FOUND, "java call needs a READY dex_id in this process");
        else {
            jbyteArray json = env->NewByteArray(static_cast<jsize>(c.len));
            if (json) env->SetByteArrayRegion(json, 0, static_cast<jsize>(c.len), reinterpret_cast<const jbyte*>(c.data));
            if (!json || env->ExceptionCheck()) artint::java_error(env, r, "copy Java request");
            else {
                jlong id = env->CallStaticLongMethod(runner, submit_id, loader, static_cast<jlong>(c.addr), json,
                                                   static_cast<jboolean>(c.args[0] == 1));
                if (env->ExceptionCheck()) artint::java_error(env, r, "submit Java request", IJ2ART_E_INVALID);
                else {
                    r.retval = static_cast<uint64_t>(id);
                    result = static_cast<jbyteArray>(env->CallStaticObjectMethod(runner, query_id, id));
                }
            }
        }
    } else if (c.type == IJ2ART_CMD_JAVA_LIST) {
        result = static_cast<jbyteArray>(env->CallStaticObjectMethod(runner, list_id));
    } else {
        result = static_cast<jbyteArray>(env->CallStaticObjectMethod(runner,
            c.type == IJ2ART_CMD_JAVA_QUERY ? query_id : drop_id, static_cast<jlong>(c.addr)));
    }
    if (!r.status) response(env, result, r);
    env->PopLocalFrame(nullptr);
    return true;
}

bool references(uint64_t dex_id, ij2art_rsp& r) {
    if (!runner) return false;
    JNIEnv* env = artint::worker_env();
    bool busy = env->CallStaticBooleanMethod(runner, refs_id, static_cast<jlong>(dex_id));
    if (env->ExceptionCheck()) {
        artint::java_error(env, r, "query Java DEX references"); return true;
    }
    if (busy) artint::message(r, IJ2ART_E_BUSY, "DEX is still referenced by a queued/running Java call");
    return busy;
}

bool shutdown(ij2art_rsp& r) {
    closing = true;
    if (!runner) return true;
    JNIEnv* env = artint::worker_env();
    bool idle = env->CallStaticBooleanMethod(runner, close_id);
    if (env->ExceptionCheck()) { artint::java_error(env, r, "close Java executor"); return false; }
    if (!idle) artint::message(r, IJ2ART_E_BUSY, "Java calls are still queued/running; retry shutdown after they finish");
    return idle;
}

void release() {
    if (runner) { artint::worker_env()->DeleteGlobalRef(runner); runner = nullptr; }
}
}
