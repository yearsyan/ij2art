// Build-bound replacement backend. Strict admission checks suspended stacks,
// JIT quiescence and old code before managed-to-native conversion.
// DEL/shutdown only close replacement admission. Native method metadata, backup
// methods, slots and their roots stay resident; physical restore is unsupported.
// Original calls use CallNonvirtual/CallStatic and the permanent managed/native backup.
#include "art_internal.h"
#include "jni_abi.h"
#include "hook_gate.h"
#include "hook_versions.h"
#include "art_backend.h"
#include <dlfcn.h>
#include <link.h>
#include "../common/hook_record.h"
#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <atomic>
#include <memory>
#include <new>
#include <string>
#include <unistd.h>

#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, "ij2art", __VA_ARGS__)

namespace ij2art::replace {
namespace {

bool g_initialized;
bool g_ever_installed;
bool g_closing;  // worker only; latched on the first shutdown attempt

// ---- cached JNI references (established by the worker thread during init) ----
struct Boxing { jclass cls; jmethodID value_of, value; };
Boxing g_box[8];  // Z B C S I J F D
jclass g_object_cls;
jfieldID g_art_method_field;   // java/lang/reflect/Executable.artMethod
jmethodID g_method_modifiers;  // Executable.getModifiers (Method or Constructor)
jmethodID g_declaring_class;   // Executable.getDeclaringClass
jmethodID g_sdk_dispatch;      // Bridge.dispatch

// Hit statistics: sharded counters plus a last-sample timestamp, each occupying its own cache
// line. The hot path writes only the calling thread's shard, so it does not evict the cache
// line holding the gate. last_hit_ms is sampled once every 16 hits per shard (including the
// first hit) and is therefore an approximation.
struct HookStats {
    static constexpr uint32_t kShards = 4;
    struct alignas(64) Shard { std::atomic<uint64_t> hits{0}; };
    Shard shards[kShards];
    alignas(64) std::atomic<uint64_t> last_ms{0};
    uint64_t hits_total() const {
        uint64_t total = 0;
        for (const auto& s : shards) total += s.hits.load(std::memory_order_relaxed);
        return total;
    }
};

struct Replacement {
    uint64_t dex_id;
    uint32_t generation;
    std::string selector;
    jobject method;
};
using Replacements = HookVersions<Replacement>;

struct HookConfig {
    // Replacement admission and logical disable have a single linearization point.
    alignas(64) HookGate gate;
    std::atomic<uint32_t> call_seq{0};
    uint32_t slot = 0;
    // Immutable once installed (read-only, so cache-line sharing is harmless).
    alignas(64) uint64_t id = 0;
    bool is_static = false;
    std::string target_sel;
    // Process-lifetime roots: DISABLED calls still use the original JNI/backup path.
    jobject target_ref = nullptr;
    jclass declaring_class = nullptr;  // declaring class (gref) for CallNonvirtual/CallStatic
    void* target = nullptr;
    void* backup = nullptr;       // backup; pointer is jmethodID (DecodeArtMethod tolerates raw)
    JniLayout layout;
    HookStats stats;
    Replacements replacements;
};

std::atomic<HookConfig*> g_slots[IJ2ART_JNI_SLOTS];
std::atomic<uint64_t> g_next_id{1};
std::atomic<uint32_t> g_shard_ticket{0};  // once per thread; round-robin stat shard assignment

uint32_t stat_shard() {
    thread_local uint32_t shard =
        g_shard_ticket.fetch_add(1, std::memory_order_relaxed) & (HookStats::kShards - 1);
    return shard;
}

struct ActiveCall { uint64_t token; HookConfig* cfg; };
thread_local ActiveCall g_calls[8];
thread_local uint32_t g_call_depth;

uint64_t now_ms() {
    timespec t{};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return uint64_t(t.tv_sec) * 1000 + t.tv_nsec / 1000000;
}

bool in_libart_exec(uint64_t addr) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    bool hit = false;
    while (fgets(line, sizeof(line), f)) {
        uint64_t s, e;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) == 3 && strchr(perms, 'x') &&
            strstr(line, "libart.so") && addr >= s && addr < e) { hit = true; break; }
    }
    fclose(f);
    return hit;
}

int cache_boxing(JNIEnv* env, int i, const char* cls, const char* factory_sig,
                 const char* value, const char* value_sig) {
    jclass local = env->FindClass(cls);
    if (!local) return -1;
    g_box[i].cls = (jclass)env->NewGlobalRef(local);
    g_box[i].value_of = env->GetStaticMethodID(local, "valueOf", factory_sig);
    g_box[i].value = env->GetMethodID(local, value, value_sig);
    env->DeleteLocalRef(local);
    return g_box[i].cls && g_box[i].value_of && g_box[i].value ? 0 : -1;
}

int cache_jni(JNIEnv* env) {
    jclass executable = env->FindClass("java/lang/reflect/Executable");
    jclass object = env->FindClass("java/lang/Object");
    if (!executable || !object) return -1;
    g_art_method_field = env->GetFieldID(executable, "artMethod", "J");
    g_method_modifiers = env->GetMethodID(executable, "getModifiers", "()I");
    g_declaring_class = env->GetMethodID(executable, "getDeclaringClass", "()Ljava/lang/Class;");
    g_object_cls = (jclass)env->NewGlobalRef(object);
    g_sdk_dispatch = env->GetStaticMethodID(artint::sdk_bridge(), "dispatch",
        "(JLjava/lang/reflect/Executable;Ljava/lang/Object;[Ljava/lang/Object;Ljava/lang/reflect/Method;)Ljava/lang/Object;");
    env->DeleteLocalRef(executable); env->DeleteLocalRef(object);
    if (!g_art_method_field || !g_method_modifiers || !g_declaring_class || !g_object_cls ||
        !g_sdk_dispatch) return -1;
    return cache_boxing(env, 0, "java/lang/Boolean", "(Z)Ljava/lang/Boolean;", "booleanValue", "()Z") |
           cache_boxing(env, 1, "java/lang/Byte", "(B)Ljava/lang/Byte;", "byteValue", "()B") |
           cache_boxing(env, 2, "java/lang/Character", "(C)Ljava/lang/Character;", "charValue", "()C") |
           cache_boxing(env, 3, "java/lang/Short", "(S)Ljava/lang/Short;", "shortValue", "()S") |
           cache_boxing(env, 4, "java/lang/Integer", "(I)Ljava/lang/Integer;", "intValue", "()I") |
           cache_boxing(env, 5, "java/lang/Long", "(J)Ljava/lang/Long;", "longValue", "()J") |
           cache_boxing(env, 6, "java/lang/Float", "(F)Ljava/lang/Float;", "floatValue", "()F") |
           cache_boxing(env, 7, "java/lang/Double", "(D)Ljava/lang/Double;", "doubleValue", "()D");
}

void* art_method_of(JNIEnv* env, jobject reflected) {
    return reinterpret_cast<void*>(env->GetLongField(reflected, g_art_method_field));
}

// Box the arguments and build an Object[]; on failure an exception is pending and nullptr is
// returned
jobjectArray box_args(JNIEnv* env, HookConfig* c, const JniCapture& saved, const void* stack) {
    size_t n = c->layout.arguments.size();
    jobjectArray arr = env->NewObjectArray((jsize)n, g_object_cls, nullptr);
    if (!arr) return nullptr;
    for (size_t i = 0; i < n; ++i) {
        uint64_t bits = jni_argument_bits(c->layout.arguments[i], saved, stack);
        jobject value = nullptr;
        switch (c->layout.arguments[i].type) {
        case 'Z': value = env->CallStaticObjectMethod(g_box[0].cls, g_box[0].value_of, (jboolean)bits); break;
        case 'B': value = env->CallStaticObjectMethod(g_box[1].cls, g_box[1].value_of, (jbyte)bits); break;
        case 'C': value = env->CallStaticObjectMethod(g_box[2].cls, g_box[2].value_of, (jchar)bits); break;
        case 'S': value = env->CallStaticObjectMethod(g_box[3].cls, g_box[3].value_of, (jshort)bits); break;
        case 'I': value = env->CallStaticObjectMethod(g_box[4].cls, g_box[4].value_of, (jint)bits); break;
        case 'J': value = env->CallStaticObjectMethod(g_box[5].cls, g_box[5].value_of, (jlong)bits); break;
        case 'F': { jfloat f; memcpy(&f, &bits, 4);
                    value = env->CallStaticObjectMethod(g_box[6].cls, g_box[6].value_of, f); break; }
        case 'D': { jdouble d; memcpy(&d, &bits, 8);
                    value = env->CallStaticObjectMethod(g_box[7].cls, g_box[7].value_of, d); break; }
        default:  value = (jobject)bits; break;  // reference passed through as-is (may be null)
        }
        if (env->ExceptionCheck()) return nullptr;
        env->SetObjectArrayElement(arr, (jsize)i, value);
        if (env->ExceptionCheck()) return nullptr;
    }
    return arr;
}

JniResult unbox_result(JNIEnv* env, HookConfig* c, jobject res) {
    if (env->ExceptionCheck()) return {0, JniReturn::GP};
    switch (c->layout.result) {
    case 'V': return {0, JniReturn::GP};
    case 'Z': return {uint64_t(uint32_t(env->CallBooleanMethod(res, g_box[0].value))), JniReturn::GP};
    case 'B': return {uint64_t(uint32_t(env->CallByteMethod(res, g_box[1].value))), JniReturn::GP};
    case 'C': return {uint64_t(uint32_t(env->CallCharMethod(res, g_box[2].value))), JniReturn::GP};
    case 'S': return {uint64_t(uint32_t(env->CallShortMethod(res, g_box[3].value))), JniReturn::GP};
    case 'I': return {uint64_t(uint32_t(env->CallIntMethod(res, g_box[4].value))), JniReturn::GP};
    case 'J': return {uint64_t(env->CallLongMethod(res, g_box[5].value)), JniReturn::GP};
    case 'F': { jfloat f = env->CallFloatMethod(res, g_box[6].value);
                uint32_t b; memcpy(&b, &f, 4); return {b, JniReturn::Float}; }
    case 'D': { jdouble d = env->CallDoubleMethod(res, g_box[7].value);
                uint64_t b; memcpy(&b, &d, 8); return {b, JniReturn::Double}; }
    default:  return {(uint64_t)res, JniReturn::GP};  // reference: jobject returned unchanged
    }
}

// Unbox: turn the Object[] coming from the SDK into a jvalue[] according to the parameter
// layout resolved at install time. Local references are reclaimed by the current JNI frame,
// so there is no per-item DeleteLocalRef. Returns false on failure, with an exception pending.
bool unbox_args(JNIEnv* env, HookConfig* c, jobjectArray arr, jvalue* out) {
    size_t n = c->layout.arguments.size();
    for (size_t i = 0; i < n; ++i) {
        jobject o = env->GetObjectArrayElement(arr, (jsize)i);
        if (env->ExceptionCheck()) return false;
        jvalue v{};  // zero-init: high bits irrelevant for narrow types, null backstop for refs
        switch (c->layout.arguments[i].type) {
        case 'Z': v.z = env->CallBooleanMethod(o, g_box[0].value); break;
        case 'B': v.b = env->CallByteMethod(o, g_box[1].value); break;
        case 'C': v.c = env->CallCharMethod(o, g_box[2].value); break;
        case 'S': v.s = env->CallShortMethod(o, g_box[3].value); break;
        case 'I': v.i = env->CallIntMethod(o, g_box[4].value); break;
        case 'J': v.j = env->CallLongMethod(o, g_box[5].value); break;
        case 'F': v.f = env->CallFloatMethod(o, g_box[6].value); break;
        case 'D': v.d = env->CallDoubleMethod(o, g_box[7].value); break;
        default:  v.l = o; break;  // reference passed through as-is (may be null)
        }
        if (env->ExceptionCheck()) return false;
        out[i] = v;
    }
    return true;
}

// Small inline argument buffer; only an over-long signature falls back to a heap allocation.
// The allocation is nothrow because a C++ exception cannot cross the assembly capture frame,
// so the caller instead turns an allocation failure into a Java OOM.
struct ArgValues {
    jvalue small[8];
    std::unique_ptr<jvalue[]> heap;
    bool ok = true;
    explicit ArgValues(size_t n) {
        if (n > 8) {
            heap.reset(new (std::nothrow) jvalue[n]);
            if (!heap) ok = false;
        }
    }
    jvalue* data() { return heap ? heap.get() : small; }
};

void throw_marshal_oom(JNIEnv* env) {
    if (env->ExceptionCheck()) return;
    jclass oom = env->FindClass("java/lang/OutOfMemoryError");
    if (oom) env->ThrowNew(oom, "hook argument marshaling");
}

// Call the saved original implementation: CallNonvirtual/CallStatic reaches the backup
// ArtMethod directly. It must be Nonvirtual -- reflective Method.invoke re-dispatches a
// virtual method using the receiver's runtime class, and the backup carries the target's
// vtable index, which would recurse back into the hooked target (confirmed on a real device).
// A managed backup executes the original DEX; a native backup reaches the current native
// binding through Generic JNI.
JniResult invoke_backup_values(JNIEnv* env, HookConfig* c, jobject receiver, const jvalue* jv) {
    jmethodID mid = (jmethodID)c->backup;
    jclass cls = c->declaring_class;
    bool st = c->is_static;
    char kind = c->layout.result;
    jobject o = nullptr;
    switch (kind) {
    case 'V': st ? env->CallStaticVoidMethodA(cls, mid, jv)
               : env->CallNonvirtualVoidMethodA(receiver, cls, mid, jv);
              return {0, JniReturn::GP};
    case 'Z': return {uint64_t(uint32_t(st ? env->CallStaticBooleanMethodA(cls, mid, jv)
               : env->CallNonvirtualBooleanMethodA(receiver, cls, mid, jv))), JniReturn::GP};
    case 'B': return {uint64_t(uint32_t(st ? env->CallStaticByteMethodA(cls, mid, jv)
               : env->CallNonvirtualByteMethodA(receiver, cls, mid, jv))), JniReturn::GP};
    case 'C': return {uint64_t(uint32_t(st ? env->CallStaticCharMethodA(cls, mid, jv)
               : env->CallNonvirtualCharMethodA(receiver, cls, mid, jv))), JniReturn::GP};
    case 'S': return {uint64_t(uint32_t(st ? env->CallStaticShortMethodA(cls, mid, jv)
               : env->CallNonvirtualShortMethodA(receiver, cls, mid, jv))), JniReturn::GP};
    case 'I': return {uint64_t(uint32_t(st ? env->CallStaticIntMethodA(cls, mid, jv)
               : env->CallNonvirtualIntMethodA(receiver, cls, mid, jv))), JniReturn::GP};
    case 'J': return {uint64_t(st ? env->CallStaticLongMethodA(cls, mid, jv)
               : env->CallNonvirtualLongMethodA(receiver, cls, mid, jv)), JniReturn::GP};
    case 'F': { jfloat f = st ? env->CallStaticFloatMethodA(cls, mid, jv)
                              : env->CallNonvirtualFloatMethodA(receiver, cls, mid, jv);
                uint32_t b; memcpy(&b, &f, 4); return {b, JniReturn::Float}; }
    case 'D': { jdouble d = st ? env->CallStaticDoubleMethodA(cls, mid, jv)
                               : env->CallNonvirtualDoubleMethodA(receiver, cls, mid, jv);
                uint64_t b; memcpy(&b, &d, 8); return {b, JniReturn::Double}; }
    default:  o = st ? env->CallStaticObjectMethodA(cls, mid, jv)
                     : env->CallNonvirtualObjectMethodA(receiver, cls, mid, jv);
              return {(uint64_t)o, JniReturn::GP};
    }
}

// Java entry point for callOriginal: the Object[] is unboxed and then the backup is called
// directly.
JniResult invoke_backup(JNIEnv* env, HookConfig* c, jobject receiver, jobjectArray args) {
    ArgValues jv(c->layout.arguments.size());
    if (!jv.ok) { throw_marshal_oom(env); return {0, JniReturn::GP}; }
    if (!unbox_args(env, c, args, jv.data())) return {0, JniReturn::GP};
    return invoke_backup_values(env, c, receiver, jv.data());
}

// Java return path of HookContext.callOriginal: primitives are boxed into objects.
jobject invoke_backup_boxed(JNIEnv* env, HookConfig* c, jobject receiver, jobjectArray args) {
    JniResult res = invoke_backup(env, c, receiver, args);
    if (env->ExceptionCheck()) return nullptr;
    switch (c->layout.result) {
    case 'V': return nullptr;
    case 'Z': return env->CallStaticObjectMethod(g_box[0].cls, g_box[0].value_of, (jboolean)res.bits);
    case 'B': return env->CallStaticObjectMethod(g_box[1].cls, g_box[1].value_of, (jbyte)res.bits);
    case 'C': return env->CallStaticObjectMethod(g_box[2].cls, g_box[2].value_of, (jchar)res.bits);
    case 'S': return env->CallStaticObjectMethod(g_box[3].cls, g_box[3].value_of, (jshort)res.bits);
    case 'I': return env->CallStaticObjectMethod(g_box[4].cls, g_box[4].value_of, (jint)res.bits);
    case 'J': return env->CallStaticObjectMethod(g_box[5].cls, g_box[5].value_of, (jlong)res.bits);
    case 'F': { jfloat f; uint32_t b = (uint32_t)res.bits; memcpy(&f, &b, 4);
                return env->CallStaticObjectMethod(g_box[6].cls, g_box[6].value_of, f); }
    case 'D': { jdouble d; memcpy(&d, &res.bits, 8);
                return env->CallStaticObjectMethod(g_box[7].cls, g_box[7].value_of, d); }
    default:  return (jobject)res.bits;
    }
}

// Convert captured values straight to jvalue, from the same source as box_args
// (jni_argument_bits). References reuse the valid local references in the generic JNI frame
// (and may be null); there is no Object[] box/unbox JNI round-trip.
jvalue capture_jvalue(const JniArgument& arg, const JniCapture& saved, const void* stack) {
    uint64_t bits = jni_argument_bits(arg, saved, stack);
    jvalue v{};
    switch (arg.type) {
    case 'Z': v.z = (jboolean)bits; break;
    case 'B': v.b = (jbyte)bits; break;
    case 'C': v.c = (jchar)bits; break;
    case 'S': v.s = (jshort)bits; break;
    case 'I': v.i = (jint)bits; break;
    case 'J': v.j = (jlong)bits; break;
    case 'F': { jfloat f; memcpy(&f, &bits, 4); v.f = f; break; }
    case 'D': { jdouble d; memcpy(&d, &bits, 8); v.d = d; break; }
    default:  v.l = (jobject)bits; break;
    }
    return v;
}

JniResult call_saved_original(JNIEnv* env, HookConfig* c, const JniCapture& saved,
                              const void* stack) {
    ArgValues jv(c->layout.arguments.size());
    if (!jv.ok) { throw_marshal_oom(env); return {0, JniReturn::GP}; }
    for (size_t i = 0; i < c->layout.arguments.size(); ++i)
        jv.data()[i] = capture_jvalue(c->layout.arguments[i], saved, stack);
    return invoke_backup_values(env, c, c->is_static ? nullptr : (jobject)saved.gp[1], jv.data());
}

void fill_record(ij2art_rsp& r, HookConfig* c) {
    const auto life = c->gate.snapshot();
    const auto& binding = c->replacements.current()->binding;
    append_hook_record(r, HookRecordView{
        c->id, c->stats.hits_total(), c->stats.last_ms.load(std::memory_order_relaxed),
        life.state, life.in_flight,
        c->target_sel, binding.selector, IJ2ART_COVERAGE_ENTRY, binding.generation});
}

HookConfig* find_hook(uint64_t id) {
    for (auto& slot : g_slots) {
        HookConfig* c = slot.load(std::memory_order_acquire);
        if (c && c->id == id) return c;
    }
    return nullptr;
}

std::string descriptor_of(const std::string& selector) {
    size_t open = selector.find('(');
    return open == std::string::npos ? std::string() : selector.substr(open);
}

} // namespace

bool available() { return g_initialized && !g_closing; }

// Only the attached control worker releases JNI roots and DEX accounting.
// Retired callback versions need no ArtMethod/stack scan: their users hold a
// lease through Bridge.dispatch and result unmarshalling. Permanent target,
// backup and current-version roots retain the existing DEL/shutdown contract.
void collect() {
    JNIEnv* env = artint::worker_env();
    if (!env) return;
    for (auto& slot : g_slots) {
        HookConfig* cfg = slot.load(std::memory_order_acquire);
        if (cfg) cfg->replacements.collect([&](const Replacement& binding) {
            env->DeleteGlobalRef(binding.method);
            artint::dex_ref_hooks(binding.dex_id, -1);
        });
    }
}

bool init(const ij2art_cmd& c, ij2art_rsp& r) {
    if (!artint::attach(r)) return false;
    JNIEnv* env = artint::worker_env();
    if (!artint::ensure_sdk(env, r)) return false;
    std::string id = artint::libart_build_id();
    const auto* match = art_profile::find(id.c_str());
    if (!match) {
        artint::message(r, 0, "{\"runtime_ready\":true,\"dex_upload\":true,\"method_lookup\":true,"
            "\"replacement\":false,\"call_original\":false,\"safe_install\":false,"
            "\"physical_restore\":false,\"delete_mode\":\"logical_disable\","
            "\"adapter\":null,\"art_build_id\":\"" + id + "\"}");
        return true;
    }
    if (c.args_n != 0 && c.args_n != 8)
        return artint::message(r, IJ2ART_E_INVALID, "HOOK_INIT accepts zero or 8 legacy libart symbol addresses"), true;
    uint64_t addrs[8]{};
    for (size_t i = 0; i < c.args_n; ++i) {
        addrs[i] = c.args[i];
        if (!addrs[i] || !in_libart_exec(addrs[i]))
            return artint::message(r, IJ2ART_E_INVALID, "symbol address outside libart executable range"), true;
    }
    uintptr_t base = 0;
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* out) {
        if (!strstr(info->dlpi_name, "/libart.so")) return 0;
        *static_cast<uintptr_t*>(out) = info->dlpi_addr;
        return 1;
    }, &base);
    if (!base)
        return artint::message(r, IJ2ART_E_UNSUPPORTED_ART, "libart load base unavailable"), true;
    if (!art_backend::initialize(*match, base, addrs, c.args_n, r)) return true;
    if (!g_initialized) {
        if (env->PushLocalFrame(16) != JNI_OK) { artint::java_error(env, r, "init local frame"); return true; }
        if (cache_jni(env) != 0) {
            env->PopLocalFrame(nullptr);
            artint::java_error(env, r, "cache JNI handles");
            return true;
        }
        env->PopLocalFrame(nullptr);
        g_initialized = true;
    }
    artint::message(r, 0, "{\"runtime_ready\":true,\"dex_upload\":true,\"method_lookup\":true,"
        "\"replacement\":true,\"replacement_update\":true,\"call_original\":true,\"safe_install\":true,"
        "\"physical_restore\":false,\"delete_mode\":\"logical_disable\","
        "\"admission\":\"entry-guard-stw-v3\",\"aot\":true,\"native\":true,\"entry_guard_hooks\":" + std::to_string(art_backend::guard_count()) + ","
        "\"native_binding_guard\":true,\"backend\":\"" + match->name + "\","
        "\"coverage\":[\"ENTRY_ONLY\"],\"full_coverage\":false,"
        "\"adapter\":\"staticcopy-v1\",\"art_build_id\":\"" + id + "\"}");
    return true;
}

void add(const ij2art_cmd& c, ij2art_rsp& r) {
    if (g_closing) {
        artint::message(r, IJ2ART_E_STATE, "Hook shutdown has started; new installs are closed");
        return;
    }
    if (!g_initialized) {
        artint::message(r, IJ2ART_E_UNSUPPORTED_ART,
            "no validated replacement adapter for libart build " + artint::libart_build_id() +
            "; target entrypoints and ART execution modes were not changed");
        return;
    }
    if (c.len < 8 || c.len > IJ2ART_CMD_DATA_MAX || (c.args[0] != IJ2ART_COVERAGE_FULL && c.args[0] != IJ2ART_COVERAGE_ENTRY)) {
        artint::message(r, IJ2ART_E_INVALID, "replacement requires a coverage mode and two method selectors");
        return;
    }
    uint32_t target_size, replacement_size;
    memcpy(&target_size, c.data, 4);
    memcpy(&replacement_size, c.data + 4, 4);
    if (uint64_t(target_size) + replacement_size + 8 != c.len || !target_size || !replacement_size) {
        artint::message(r, IJ2ART_E_INVALID, "invalid method selector lengths");
        return;
    }
    auto* entry = artint::dex_store().find(c.addr);
    jobject dex_loader = artint::dex_loader_for(c.addr);
    if (!entry) { artint::message(r, IJ2ART_E_NOT_FOUND, "unknown dex_id in this process"); return; }
    if (entry->info.state != IJ2ART_DEX_READY || !dex_loader) {
        artint::message(r, IJ2ART_E_STATE, "dex_id is not loaded; finish dex upload first");
        return;
    }
    if (!artint::attach(r)) return;
    JNIEnv* env = artint::worker_env();
    if (!artint::ensure_sdk(env, r)) return;

    std::string target_sel((char*)c.data + 8, target_size);
    std::string replacement_sel((char*)c.data + 8 + target_size, replacement_size);
    JniLayout layout;
    std::string layout_error;
    if (!jni_layout(descriptor_of(target_sel), layout, layout_error)) {
        artint::message(r, IJ2ART_E_SIGNATURE, "target descriptor: " + layout_error);
        return;
    }
    if (env->PushLocalFrame(32) != JNI_OK) { artint::java_error(env, r, "hook local frame"); return; }
    do {
        // 1) resolve (the Java-side Bridge validates the signature, the modifiers and the
        // loader ownership)
        jstring jt = env->NewStringUTF(target_sel.c_str());
        jstring jr = jt ? env->NewStringUTF(replacement_sel.c_str()) : nullptr;
        jobject pair = nullptr;
        if (jr) {
            jmethodID resolve = env->GetStaticMethodID(artint::sdk_bridge(), "resolveReplacement",
                "(Ljava/lang/ClassLoader;Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/reflect/Executable;");
            pair = env->CallStaticObjectMethod(artint::sdk_bridge(), resolve,
                artint::app_loader(), dex_loader, jt, jr);
        }
        if (!pair || env->ExceptionCheck()) {
            artint::java_error(env, r, "resolve target/replacement", IJ2ART_E_SIGNATURE);
            break;
        }
        auto* methods = (jobjectArray)pair;
        jobject target_m = env->GetObjectArrayElement(methods, 0);
        jobject replacement_m = env->GetObjectArrayElement(methods, 1);
        if (!target_m || !replacement_m) { artint::java_error(env, r, "read resolved methods"); break; }

        if (c.args[0] == IJ2ART_COVERAGE_FULL) {
            artint::message(r, IJ2ART_E_COVERAGE,
                "FULL coverage is unavailable: existing inlined callers cannot be intercepted; "
                "request ENTRY_ONLY explicitly to use strict conversion admission");
            break;
        }
        bool is_static = (env->CallIntMethod(target_m, g_method_modifiers) & 0x8) != 0;
        if (env->ExceptionCheck()) { artint::java_error(env, r, "read target modifiers"); break; }
        void* t = art_method_of(env, target_m);
        if (!t || env->ExceptionCheck()) { artint::java_error(env, r, "read target ArtMethod"); break; }
        bool dup = false;
        for (auto& slot : g_slots) {
            HookConfig* old = slot.load(std::memory_order_acquire);
            if (old && old->target == t) { dup = true; break; }
        }
        if (dup) { artint::message(r, IJ2ART_E_STATE, "target retains a Hook slot; physical restore/reinstall unsupported"); break; }

        // Initialization may execute user code: keep it outside STW/ART locks,
        // and after coverage/duplicate validation. Failure leaves no hook slot.
        jmethodID initialize = env->GetStaticMethodID(artint::sdk_bridge(), "initializeTarget",
            "(Ljava/lang/reflect/Executable;)V");
        if (initialize) env->CallStaticVoidMethod(artint::sdk_bridge(), initialize, target_m);
        if (!initialize || env->ExceptionCheck()) {
            artint::java_error(env, r, "initialize target class");
            break;
        }

        // 3) slot and backup (a real declared SDK method; CopyFrom copies the target into it)
        int slot = -1;
        for (int i = 0; i < (int)IJ2ART_JNI_SLOTS; ++i)
            if (!g_slots[i].load(std::memory_order_acquire)) { slot = i; break; }
        if (slot < 0) { artint::message(r, IJ2ART_E_LIMIT, "128 hook slots exhausted"); break; }
        char backup_name[16];
        snprintf(backup_name, sizeof(backup_name), "s%d", slot);
        jmethodID backup_id = env->GetStaticMethodID(artint::sdk_backup(), backup_name, "()V");
        if (!backup_id) { artint::java_error(env, r, "locate backup slot method"); break; }
        jobject backup_pre = env->ToReflectedMethod(artint::sdk_backup(), backup_id, JNI_TRUE);
        if (!backup_pre) { artint::java_error(env, r, "reflect backup method"); break; }
        void* backup = art_method_of(env, backup_pre);
        if (!backup || env->ExceptionCheck()) { artint::java_error(env, r, "read backup ArtMethod"); break; }
        jobject declaring = env->CallObjectMethod(target_m, g_declaring_class);
        if (!declaring || env->ExceptionCheck()) { artint::java_error(env, r, "read declaring class"); break; }
        jobject target_gr = env->NewGlobalRef(target_m);
        jobject replacement_gr = replacement_m ? env->NewGlobalRef(replacement_m) : nullptr;
        jclass declaring_gr = declaring ? (jclass)env->NewGlobalRef(declaring) : nullptr;
        if (!target_gr || !replacement_gr || !declaring_gr) {
            if (target_gr) env->DeleteGlobalRef(target_gr);
            if (replacement_gr) env->DeleteGlobalRef(replacement_gr);
            if (declaring_gr) env->DeleteGlobalRef(declaring_gr);
            artint::java_error(env, r, "retain method refs");
            break;
        }

        auto cfg_owner = std::make_unique<HookConfig>();
        HookConfig* cfg = cfg_owner.get();
        cfg->id = g_next_id.fetch_add(1, std::memory_order_relaxed);
        cfg->slot = (uint32_t)slot;
        cfg->is_static = is_static;
        cfg->target_sel = target_sel;
        cfg->layout = std::move(layout);
        cfg->target = t;
        cfg->backup = backup;
        cfg->target_ref = target_gr;
        cfg->declaring_class = declaring_gr;
        auto binding = std::make_unique<Replacements::Version>(
            Replacement{c.addr, 1, replacement_sel, replacement_gr});
        cfg->replacements.publish(binding.get());

        // The backend publishes the slot while mutators are still suspended.
        auto admitted = art_backend::install(t, backup, ij2art_jni_slots[slot], [](void* opaque) {
            auto* installed = static_cast<HookConfig*>(opaque);
            g_ever_installed = true;
            g_slots[installed->slot].store(installed, std::memory_order_release);
        }, cfg);
        if (!admitted) {
            env->DeleteGlobalRef(target_gr);
            env->DeleteGlobalRef(replacement_gr);
            env->DeleteGlobalRef(declaring_gr);
            artint::message(r, admitted.status, admitted.reason);
            break;
        }

        // 5) refcount and ownership wrap-up. There is no failure path beyond this point, and
        // the dex reference is serialized with dex del on the control plane, so no critical
        // zone is needed
        artint::dex_ref_hooks(c.addr, +1);
        binding.release();
        cfg_owner.release();  // Stable target/backup slot stays alive until exit.
        r.retval = cfg->id;
        fill_record(r, cfg);
        ALOGI("hook installed: id=%llu slot=%d target=%s", (unsigned long long)cfg->id, slot,
              target_sel.c_str());
        env->PopLocalFrame(nullptr);
        return;
    } while (false);
    env->PopLocalFrame(nullptr);
}

void update(const ij2art_cmd& c, ij2art_rsp& r) {
    if (g_closing) {
        artint::message(r, IJ2ART_E_STATE, "Hook shutdown has started; updates are closed");
        return;
    }
    HookConfig* cfg = find_hook(c.addr);
    if (!cfg) { artint::message(r, IJ2ART_E_NOT_FOUND, "unknown hook_id"); return; }
    if (!c.len || c.len > IJ2ART_CMD_DATA_MAX || memchr(c.data, 0, c.len)) {
        artint::message(r, IJ2ART_E_INVALID, "update requires a replacement selector");
        return;
    }
    auto* dex = artint::dex_store().find(c.args[0]);
    jobject loader = artint::dex_loader_for(c.args[0]);
    if (!dex) { artint::message(r, IJ2ART_E_NOT_FOUND, "unknown dex_id in this process"); return; }
    if (dex->info.state != IJ2ART_DEX_READY || !loader) {
        artint::message(r, IJ2ART_E_STATE, "dex_id is not loaded; finish dex upload first");
        return;
    }
    const auto& previous = cfg->replacements.current()->binding;
    if (previous.generation == UINT32_MAX) {
        artint::message(r, IJ2ART_E_LIMIT, "Hook replacement generation exhausted");
        return;
    }
    if (!artint::attach(r)) return;
    JNIEnv* env = artint::worker_env();
    if (env->PushLocalFrame(16) != JNI_OK) { artint::java_error(env, r, "update local frame"); return; }
    std::string selector(reinterpret_cast<const char*>(c.data), c.len);
    do {
        jstring name = env->NewStringUTF(selector.c_str());
        jmethodID resolve = name ? env->GetStaticMethodID(artint::sdk_bridge(), "resolveHandler",
            "(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/reflect/Method;") : nullptr;
        jobject method = resolve ? env->CallStaticObjectMethod(artint::sdk_bridge(), resolve, loader, name) : nullptr;
        if (!method || env->ExceptionCheck()) {
            artint::java_error(env, r, "resolve replacement", IJ2ART_E_SIGNATURE);
            break;
        }
        // Initialize before publication, with no slot lock held. A failing
        // <clinit> must not replace a working callback. Target stays untouched.
        jmethodID initialize = env->GetStaticMethodID(artint::sdk_bridge(), "initializeTarget",
            "(Ljava/lang/reflect/Executable;)V");
        if (initialize) env->CallStaticVoidMethod(artint::sdk_bridge(), initialize, method);
        if (!initialize || env->ExceptionCheck()) {
            artint::java_error(env, r, "initialize replacement class");
            break;
        }
        jobject retained = env->NewGlobalRef(method);
        if (!retained) { artint::java_error(env, r, "retain replacement method"); break; }
        std::unique_ptr<Replacements::Version> next(new (std::nothrow) Replacements::Version(
            Replacement{c.args[0], previous.generation + 1, std::move(selector), retained}));
        if (!next) {
            env->DeleteGlobalRef(retained);
            artint::message(r, IJ2ART_E_LIMIT, "could not allocate replacement version");
            break;
        }
        // DEX commands and lifecycle writes are serialized by the worker.
        // From here publication cannot fail; no JNI under the slot lock.
        artint::dex_ref_hooks(c.args[0], +1);
        cfg->replacements.publish(next.release());
        collect();
        r.retval = cfg->id;
        fill_record(r, cfg);
    } while (false);
    env->PopLocalFrame(nullptr);
}

void del(const ij2art_cmd& c, ij2art_rsp& r) {
    HookConfig* cfg = find_hook(c.addr);
    if (!cfg) { artint::message(r, IJ2ART_E_NOT_FOUND, "unknown hook_id"); return; }
    cfg->gate.disable();  // No ArtMethod writes, STW or root releases, even when idle.
    fill_record(r, cfg);  // DRAINING becomes DISABLED when the last ticket leaves.
}

void query(const ij2art_cmd& c, ij2art_rsp& r) {
    HookConfig* cfg = find_hook(c.addr);
    if (!cfg) { artint::message(r, IJ2ART_E_NOT_FOUND, "unknown hook_id"); return; }
    fill_record(r, cfg);
}

void list(ij2art_rsp& r) {
    for (auto& slot : g_slots) {
        HookConfig* c = slot.load(std::memory_order_acquire);
        if (!c) continue;
        // Disabled slots still own methods/DEX roots; keep them visible.
        fill_record(r, c);
        if (r.flags & 1) break;  // truncated: helper guarantees no byte was written; wrap up
    }
}

bool shutdown_all(bool& retain_sdk) {
    g_closing = true;
    retain_sdk = g_ever_installed;
    for (auto& slot : g_slots) {
        HookConfig* c = slot.load(std::memory_order_acquire);
        if (c) c->gate.disable();
    }
    for (auto& slot : g_slots) {
        HookConfig* c = slot.load(std::memory_order_acquire);
        if (c && c->gate.snapshot().in_flight != 0) return false;
    }
    collect();
    return true;
}

} // namespace ij2art::replace

// ---- hit path: a permanent slot, with one leased replacement version per call ----
extern "C" ij2art::JniResult ij2art_jni_dispatch(uint64_t slot, const ij2art::JniCapture* saved,
                                                     const void* incoming_stack) {
    using namespace ij2art;
    using namespace ij2art::replace;
    if (slot >= IJ2ART_JNI_SLOTS) return {0, JniReturn::GP};
    HookConfig* cfg = g_slots[slot].load(std::memory_order_acquire);
    if (!cfg) return {0, JniReturn::GP};
    JNIEnv* env = reinterpret_cast<JNIEnv*>(saved->gp[0]);
    uint64_t hits = cfg->stats.shards[stat_shard()].hits.fetch_add(1, std::memory_order_relaxed) + 1;
    if ((hits & 15) == 1)  // sampled 1-in-16 per shard (incl. first); last_hit_ms approximate
        cfg->stats.last_ms.store(now_ms(), std::memory_order_relaxed);
    bool recursive = false;
    for (uint32_t i = 0; i < g_call_depth; ++i)
        if (g_calls[i].cfg == cfg) { recursive = true; break; }
    if (recursive || g_call_depth >= 8 || !cfg->gate.try_enter())
        return call_saved_original(env, cfg, *saved, incoming_stack);
    auto* binding = cfg->replacements.acquire();
    struct Guard {
        HookConfig* c;
        Replacements::Version* binding;
        ~Guard() { Replacements::release(binding); c->gate.leave(); }
    } guard{cfg, binding};

    jobjectArray arr = box_args(env, cfg, *saved, incoming_stack);
    if (!arr) return {0, JniReturn::GP};
    uint64_t token = (cfg->id << 32) | cfg->call_seq.fetch_add(1, std::memory_order_relaxed);
    g_calls[g_call_depth++] = {token, cfg};
    jobject res = env->CallStaticObjectMethod(ij2art::artint::sdk_bridge(), g_sdk_dispatch, (jlong)token,
        cfg->target_ref, cfg->is_static ? nullptr : (jobject)saved->gp[1], arr, binding->binding.method);
    --g_call_depth;
    return unbox_result(env, cfg, res);
}

// HookContext.callOriginalNative: the token must belong to the innermost active call on this
// thread.
extern "C" JNIEXPORT jobject ij2art_hook_call_original(JNIEnv* env, jclass, jlong token,
                                                         jobject receiver, jobjectArray args) {
    using namespace ij2art::replace;
    jclass error = env->FindClass("java/lang/IllegalStateException");
    if (!g_call_depth || uint64_t(token) != g_calls[g_call_depth - 1].token) {
        if (error) env->ThrowNew(error, "invalid or stale original-call token");
        return nullptr;
    }
    HookConfig* cfg = g_calls[g_call_depth - 1].cfg;
    return invoke_backup_boxed(env, cfg, receiver, args);
}
