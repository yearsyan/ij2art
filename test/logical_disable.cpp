// Integration fixture ONLY; never linked into payload.so. Exercise the real
// dispatcher/DEL/QUERY/LIST/shutdown code using legitimately declared JNI methods.
// No managed ArtMethod conversion, CopyFrom, SuspendAll or unsafe install bypass.
#include "../payload/replace.cpp"
#include <cstdlib>

namespace {
JNIEnv* fixture_env;
jclass fixture_bridge, fixture_backup;
DexStore fixture_dex{17};
uint64_t fixture_dex_id;

void require(bool ok, const char* message) {
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::abort(); }
}
}

// Only ART integration dependencies are fixture-owned. Production replacement
// lifecycle code above, including its DEX retain/release calls, is unmodified.
namespace ij2art::artint {
int message(ij2art_rsp& r, int code, const std::string& text) {
    r.status = code;
    r.len = std::min(text.size(), size_t(IJ2ART_RSP_DATA_MAX));
    memcpy(r.data, text.data(), r.len);
    return code;
}
int java_error(JNIEnv*, ij2art_rsp& r, const char* op, int code) { return message(r, code, op); }
bool attach(ij2art_rsp&) { return true; }
JNIEnv* worker_env() { return fixture_env; }
jobject app_loader() { return nullptr; }
bool ensure_sdk(JNIEnv*, ij2art_rsp&) { return true; }
DexStore& dex_store() { return fixture_dex; }
jobject dex_loader_for(uint64_t) { return nullptr; }
void dex_ref_hooks(uint64_t id, int delta) {
    auto* entry = fixture_dex.find(id);
    require(entry != nullptr, "lost pinned DEX");
    entry->info.hook_refs += delta;
}
std::string libart_build_id() { return {}; }
jclass sdk_bridge() { return fixture_bridge; }
jclass sdk_backup() { return fixture_backup; }
}

using namespace ij2art;
using namespace ij2art::replace;

// This fixture tests the dispatcher on declared JNI methods. It never installs
// an ART backend; fail closed if a test accidentally requests conversion.
namespace ij2art::art_backend {
bool initialize(const art_profile::Profile&, uintptr_t, const uint64_t*, size_t, ij2art_rsp&) { return false; }
size_t guard_count() { return 0; }
Result install(void*, void*, void*, void(*)(void*), void*) {
    return {IJ2ART_E_UNSUPPORTED_ART, "lifecycle fixture does not convert ArtMethods"};
}
}

extern "C" JNIEXPORT void JNICALL
Java_org_ij2art_LogicalDisable_setup(JNIEnv* env, jclass cls) {
    fixture_env = env;
    fixture_bridge = (jclass)env->NewGlobalRef(env->FindClass("org/ij2art/Bridge"));
    fixture_backup = (jclass)env->NewGlobalRef(env->FindClass("org/ij2art/Backup"));
    require(cache_jni(env) == 0 && !env->ExceptionCheck(), "cache JNI");
    jclass context = env->FindClass("org/ij2art/HookContext");
    JNINativeMethod original{const_cast<char*>("callOriginalNative"),
        const_cast<char*>("(JLjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"),
        (void*)ij2art_hook_call_original};
    require(env->RegisterNatives(context, &original, 1) == JNI_OK, "register original API");
    DexStore::Entry* dex;
    require(fixture_dex.begin(1, 112, 0, dex) == 0, "create accounting entry");
    fixture_dex_id = dex->info.id;
    jmethodID replacement = env->GetStaticMethodID(cls, "replace",
        "(Lorg/ij2art/HookContext;)Ljava/lang/Object;");
    require(replacement != nullptr, "replacement method");
    const char* names[] = {"target", "targetRef", "targetDouble"};
    const char* originals[] = {"original", "originalRef", "originalDouble"};
    const char* sigs[] = {"(I)I", "(Ljava/lang/String;)Ljava/lang/String;", "(D)D"};
    for (unsigned i = 0; i < 3; ++i) {
        jmethodID target = env->GetStaticMethodID(cls, names[i], sigs[i]);
        jmethodID backup = env->GetStaticMethodID(cls, originals[i], sigs[i]);
        require(target && backup, "fixture target/backup");
        auto* cfg = new HookConfig;
        cfg->id = i + 1;
        cfg->slot = i;
        cfg->is_static = true;
        cfg->target_ref = env->NewGlobalRef(env->ToReflectedMethod(cls, target, JNI_TRUE));
        auto replacement_ref = env->NewGlobalRef(env->ToReflectedMethod(cls, replacement, JNI_TRUE));
        cfg->replacements.publish(new Replacements::Version(Replacement{fixture_dex_id, 1,
            "org.ij2art.LogicalDisable.replace", replacement_ref}));
        cfg->declaring_class = (jclass)env->NewGlobalRef(cls);
        cfg->target = art_method_of(env, cfg->target_ref);
        // Actual JNI-created method ID for an unchanged managed original, not a copy.
        cfg->backup = reinterpret_cast<void*>(backup);
        cfg->target_sel = std::string("org.ij2art.LogicalDisable.") + names[i] + sigs[i];
        std::string error;
        require(jni_layout(sigs[i], cfg->layout, error), "layout");
        artint::dex_ref_hooks(fixture_dex_id, 1);
        g_slots[i].store(cfg, std::memory_order_release);
        JNINativeMethod native{const_cast<char*>(names[i]), const_cast<char*>(sigs[i]), ij2art_jni_slots[i]};
        require(env->RegisterNatives(cls, &native, 1) == JNI_OK, "register declared native target");
    }
    g_ever_installed = true;
}

extern "C" JNIEXPORT jint JNICALL
Java_org_ij2art_LogicalDisable_disable(JNIEnv*, jclass, jint slot) {
    HookConfig* cfg = g_slots[slot].load();
    auto* target = static_cast<unsigned char*>(cfg->target);
    uint32_t flags;
    void* data;
    memcpy(&flags, target + 4, sizeof(flags));
    memcpy(&data, target + 16, sizeof(data));
    ij2art_cmd cmd{};
    cmd.addr = cfg->id;
    ij2art_rsp rsp{};
    del(cmd, rsp);
    require(rsp.status == 0, "DEL status");
    require(!memcmp(target + 4, &flags, sizeof(flags)) && !memcmp(target + 16, &data, sizeof(data)),
            "DEL rewrote target metadata");
    require((flags & 0x100) != 0, "target must remain native");
    require(fixture_dex.drop(fixture_dex_id) == IJ2ART_E_BUSY, "disabled DEX must remain charged");
    rsp = {};
    query(cmd, rsp);
    ij2art_hook_info info{};
    memcpy(&info, rsp.data, sizeof(info));
    rsp = {};
    list(rsp);
    require(rsp.len > 3 * sizeof(info), "disabled slots disappeared from LIST");
    return (jint)info.state;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_org_ij2art_LogicalDisable_shutdown(JNIEnv*, jclass) {
    bool retain = false;
    bool drained = shutdown_all(retain);
    require(retain, "shutdown must retain SDK");
    require(fixture_dex.find(fixture_dex_id)->info.hook_refs == 3, "shutdown released permanent DEX roots");
    ij2art_cmd cmd{};
    ij2art_rsp rsp{};
    add(cmd, rsp);
    require(rsp.status == IJ2ART_E_STATE, "shutdown did not latch installation closure");
    return drained;
}
