#include "art.h"
#include "art_internal.h"
#include "dex_store.h"
#include "hook_sdk.h"
#include "java_calls.h"
#include "ring.h"
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace {
pthread_mutex_t ready_mutex = PTHREAD_MUTEX_INITIALIZER;
JavaVM* ready_vm;
jobject ready_loader;
bool closed;
// Everything below is accessed only by the ring worker.
JNIEnv* worker_env;
JavaVM* worker_vm;
jobject sdk_loader;
jclass bridge_class;
jclass backup_class;
jmethodID resolve_replacement;
struct LoadedDex { uint64_t id = 0; jobject loader = nullptr; jobject bytes = nullptr; };
std::array<LoadedDex, IJ2ART_DEX_SLOTS> loaded;

DexStore& store() {
    static DexStore value(arc4random());
    return value;
}
uint64_t now_ms() {
    timespec t{};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return uint64_t(t.tv_sec) * 1000 + t.tv_nsec / 1000000;
}
int message(ij2art_rsp& r, int error, const std::string& text) {
    r.status = error;
    r.len = std::min(text.size(), size_t(IJ2ART_RSP_DATA_MAX));
    memcpy(r.data, text.data(), r.len);
    return error;
}
int java_error(JNIEnv* env, ij2art_rsp& r, const char* operation, int code = IJ2ART_E_JAVA) {
    std::string detail(operation);
    if (env->ExceptionCheck()) {
        jthrowable thrown = env->ExceptionOccurred();
        env->ExceptionClear();
        jclass cls = env->GetObjectClass(thrown);
        jmethodID stringify = cls ? env->GetMethodID(cls, "toString", "()Ljava/lang/String;") : nullptr;
        auto text = stringify ? (jstring)env->CallObjectMethod(thrown, stringify) : nullptr;
        if (!env->ExceptionCheck() && text) {
            const char* chars = env->GetStringUTFChars(text, nullptr);
            if (chars) { detail += ": "; detail += chars; env->ReleaseStringUTFChars(text, chars); }
        }
        // Only the management worker's failed JNI operation is cleared here.
        env->ExceptionClear();
    }
    return message(r, code, detail);
}
// Resolve the runtime address of an exported symbol by name, using the dynsym of a module
// that is already loaded in this process. dlopen/dlsym is blocked by the linker namespace
// (libart is not visible from the default namespace that the payload lives in), so the only
// option is to read memory directly through dl_iterate_phdr + PT_DYNAMIC. For the number of
// dynsym entries we prefer DT_HASH.nchain, and when that is missing we infer it from the tail
// of the GNU hash chain; the rules match the CLI's remote resolution (cli/src/elf.rs MemElf).
struct DynsymCtx {
    const char* module;
    const char* name;
    uintptr_t result;
};
static int dynsym_cb(dl_phdr_info* info, size_t, void* data) {
    DynsymCtx* c = static_cast<DynsymCtx*>(data);
    if (!strstr(info->dlpi_name, c->module)) return 0;
    uintptr_t base = info->dlpi_addr;
    uintptr_t dynamic = 0;
    for (int i = 0; i < info->dlpi_phnum; ++i)
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC)
            dynamic = base + info->dlpi_phdr[i].p_vaddr;
    if (!dynamic) return 0;
    // d_ptr values in .dynamic keep their link-time vaddr, which is far below the runtime
    // base address; normalize them on that basis
    auto absolute = [base](uintptr_t v) { return v < base ? v + base : v; };
    uintptr_t strtab = 0, symtab = 0, hash = 0, gnu_hash = 0;
    for (int i = 0; i < 128; ++i) {
        Elf64_Dyn* e = reinterpret_cast<Elf64_Dyn*>(dynamic) + i;
        if (e->d_tag == DT_NULL) break;
        if (e->d_tag == DT_STRTAB) strtab = e->d_un.d_ptr;
        else if (e->d_tag == DT_SYMTAB) symtab = e->d_un.d_ptr;
        else if (e->d_tag == DT_HASH) hash = e->d_un.d_ptr;
        else if (e->d_tag == DT_GNU_HASH) gnu_hash = e->d_un.d_ptr;
    }
    if (!strtab || !symtab) return 0;
    strtab = absolute(strtab);
    symtab = absolute(symtab);
    hash = hash ? absolute(hash) : 0;
    gnu_hash = gnu_hash ? absolute(gnu_hash) : 0;
    size_t count = 0;
    if (hash) {
        count = reinterpret_cast<uint32_t*>(hash)[1];  // nchain is the dynsym entry count
    } else if (gnu_hash) {
        uint32_t* h = reinterpret_cast<uint32_t*>(gnu_hash);
        uint32_t nbuckets = h[0], symndx = h[1], bloom = h[2];
        if (!nbuckets || nbuckets >= 0x100000 || bloom >= 0x10000) return 0;
        uint32_t* buckets = h + 4 + bloom * 2;  // 16-byte header + bloom (64-bit words)
        uint32_t maxb = symndx ? symndx - 1 : 0;
        for (uint32_t i = 0; i < nbuckets; ++i)
            if (buckets[i] > maxb) maxb = buckets[i];
        uint32_t* chain = buckets + nbuckets;
        uint32_t i = maxb;
        while (i >= symndx && i < 0x100000) {
            if (chain[i - symndx] & 1) break;  // a set low bit marks the end of the chain
            ++i;
        }
        count = i + 1;
    } else if (strtab > symtab) {
        count = (strtab - symtab) / sizeof(Elf64_Sym);  // fallback based on the lld layout
    }
    if (!count || count >= 0x100000) return 0;
    for (size_t i = 0; i < count; ++i) {
        Elf64_Sym* s = reinterpret_cast<Elf64_Sym*>(symtab) + i;
        if (s->st_value &&
            !strcmp(reinterpret_cast<const char*>(strtab + s->st_name), c->name)) {
            c->result = base + s->st_value;
            return 1;
        }
    }
    return 0;
}
static uintptr_t module_dynsym_lookup(const char* module, const char* name) {
    DynsymCtx ctx{module, name, 0};
    dl_iterate_phdr(dynsym_cb, &ctx);
    return ctx.result;
}

// Lazy bootstrap: when the App does not deliver runtime_ready, the control worker establishes
// readiness on its own behalf. It uses only the public JNI Invocation API and the public Java
// API, with no dependency on ART's private ABI. It returns nullptr while the Application does
// not exist yet and leaves the attempt for the next command to retry: falling back to the
// system ClassLoader at that point would be latched permanently by runtime_ready's set-once
// behavior, so a temporary failure is preferable. The system loader fallback is used only when
// the currentApplication path is blocked (for example by hidden API interception). On success
// it returns ready_vm; no failure path modifies existing state.
JavaVM* bootstrap_runtime() {
    pthread_mutex_lock(&ready_mutex);
    bool stopped = closed || ready_vm != nullptr;
    pthread_mutex_unlock(&ready_mutex);
    if (stopped) return nullptr;
    auto get_created_vms = reinterpret_cast<jint (*)(JavaVM**, jsize, jsize*)>(
        module_dynsym_lookup("/libart.so", "JNI_GetCreatedJavaVMs"));
    JavaVM* vm = nullptr;
    jsize found = 0;
    if (!get_created_vms || get_created_vms(&vm, 1, &found) != JNI_OK || found != 1 || !vm)
        return nullptr;
    JNIEnv* env = nullptr;
    // The attach name becomes the Java Thread's name and, via ART's CreatePeer, this TID's
    // new comm — it must repeat the worker's disguise instead of carrying a plaintext tag.
    JavaVMAttachArgs args{JNI_VERSION_1_6, const_cast<char*>(ij2art_ring_worker_name()), nullptr};
    if (vm->AttachCurrentThreadAsDaemon(&env, &args) != JNI_OK || !env) return nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    jobject loader = nullptr;
    jclass activity_thread = env->FindClass("android/app/ActivityThread");
    if (!activity_thread) env->ExceptionClear();
    jmethodID current_app = activity_thread ? env->GetStaticMethodID(activity_thread,
        "currentApplication", "()Landroid/app/Application;") : nullptr;
    if (activity_thread && !current_app && env->ExceptionCheck()) env->ExceptionClear();
    if (current_app) {
        jobject app = env->CallStaticObjectMethod(activity_thread, current_app);
        if (env->ExceptionCheck()) { env->ExceptionClear(); app = nullptr; }
        if (app) {
            jclass application = env->FindClass("android/app/Application");
            if (!application) env->ExceptionClear();
            jmethodID get_loader = application ? env->GetMethodID(application, "getClassLoader",
                "()Ljava/lang/ClassLoader;") : nullptr;
            if (application && !get_loader && env->ExceptionCheck()) env->ExceptionClear();
            if (get_loader) {
                loader = env->CallObjectMethod(app, get_loader);
                if (env->ExceptionCheck()) { env->ExceptionClear(); loader = nullptr; }
            }
            if (application) env->DeleteLocalRef(application);
            env->DeleteLocalRef(app);
        }
    }
    if (activity_thread) env->DeleteLocalRef(activity_thread);
    if (!loader && !current_app) {
        jclass loader_class = env->FindClass("java/lang/ClassLoader");
        if (!loader_class) { env->ExceptionClear(); return nullptr; }
        jmethodID system_loader = env->GetStaticMethodID(loader_class, "getSystemClassLoader",
            "()Ljava/lang/ClassLoader;");
        if (!system_loader) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            env->DeleteLocalRef(loader_class);
            return nullptr;
        }
        loader = env->CallStaticObjectMethod(loader_class, system_loader);
        if (env->ExceptionCheck()) { env->ExceptionClear(); loader = nullptr; }
        env->DeleteLocalRef(loader_class);
    }
    if (!loader) return nullptr;
    bool accepted = ij2art_runtime_ready(env, loader);
    env->DeleteLocalRef(loader);
    if (!accepted) return nullptr;
    pthread_mutex_lock(&ready_mutex);
    JavaVM* ready = closed ? nullptr : ready_vm;
    pthread_mutex_unlock(&ready_mutex);
    return ready;
}
bool attach(ij2art_rsp& r) {
    if (worker_env) return true;
    pthread_mutex_lock(&ready_mutex);
    JavaVM* vm = closed ? nullptr : ready_vm;
    pthread_mutex_unlock(&ready_mutex);
    // When the target App does not deliver runtime_ready, bootstrap lazily on the first
    // command that needs an env.
    if (!vm) vm = bootstrap_runtime();
    if (!vm) {
        message(r, IJ2ART_E_NOT_READY,
            "runtime not ready: no App-delivered readiness and worker bootstrap failed");
        return false;
    }
    JavaVMAttachArgs args{JNI_VERSION_1_6, const_cast<char*>(ij2art_ring_worker_name()), nullptr};
    JNIEnv* env = nullptr;
    if (vm->AttachCurrentThreadAsDaemon(&env, &args) != JNI_OK) {
        message(r, IJ2ART_E_NOT_READY, "AttachCurrentThreadAsDaemon failed");
        return false;
    }
    worker_vm = vm;
    worker_env = env;
    return true;
}
jobject make_loader(JNIEnv* env, const uint8_t* bytes, size_t size, jobject parent, jobject& array) {
    auto data = env->NewByteArray(static_cast<jsize>(size));
    if (!data) return nullptr;
    env->SetByteArrayRegion(data, 0, static_cast<jsize>(size), reinterpret_cast<const jbyte*>(bytes));
    if (env->ExceptionCheck()) return nullptr;
    jclass buffer_class = env->FindClass("java/nio/ByteBuffer");
    if (!buffer_class) return nullptr;
    jmethodID wrap = env->GetStaticMethodID(buffer_class, "wrap", "([B)Ljava/nio/ByteBuffer;");
    if (!wrap) return nullptr;
    jobject buffer = env->CallStaticObjectMethod(buffer_class, wrap, data);
    if (!buffer || env->ExceptionCheck()) return nullptr;
    jclass loader_class = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!loader_class) return nullptr;
    jmethodID ctor = env->GetMethodID(loader_class, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!ctor) return nullptr;
    jobject loader = env->NewObject(loader_class, ctor, buffer, parent);
    if (!loader || env->ExceptionCheck()) return nullptr;
    array = data;
    return loader;
}
jclass load_class(JNIEnv* env, jobject loader, const char* name) {
    jclass cls = env->FindClass("java/lang/ClassLoader");
    if (!cls) return nullptr;
    jmethodID load = env->GetMethodID(cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load) return nullptr;
    jstring text = env->NewStringUTF(name);
    if (!text) return nullptr;
    return (jclass)env->CallObjectMethod(loader, load, text);
}
// The real implementation of HookContext.callOriginalNative is provided by replace.cpp. When
// there is no valid token (the backend has not installed any hook), it only throws
// IllegalStateException.
extern "C" jobject ij2art_hook_call_original(JNIEnv*, jclass, jlong, jobject, jobjectArray);

bool ensure_sdk(JNIEnv* env, ij2art_rsp& r) {
    if (sdk_loader) return true;
    jobject bytes = nullptr;
    jobject loader = make_loader(env, ij2art_hook_sdk, sizeof(ij2art_hook_sdk), ready_loader, bytes);
    if (!loader) { java_error(env, r, "load Hook SDK"); return false; }
    jclass bridge = load_class(env, loader, "org.ij2art.Bridge");
    if (!bridge || env->ExceptionCheck()) { java_error(env, r, "load Bridge"); return false; }
    jclass context = load_class(env, loader, "org.ij2art.HookContext");
    if (!context || env->ExceptionCheck()) { java_error(env, r, "load HookContext"); return false; }
    jclass backup = load_class(env, loader, "org.ij2art.Backup");
    if (!backup || env->ExceptionCheck()) { java_error(env, r, "load Backup"); return false; }
    JNINativeMethod methods[] = {{const_cast<char*>("callOriginalNative"),
        const_cast<char*>("(JLjava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;"), (void*)ij2art_hook_call_original}};
    if (env->RegisterNatives(context, methods, 1) != JNI_OK) {
        java_error(env, r, "register HookContext natives"); return false;
    }
    jmethodID resolve = env->GetStaticMethodID(bridge, "resolveReplacement",
        "(Ljava/lang/ClassLoader;Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/lang/String;)[Ljava/lang/reflect/Executable;");
    if (!resolve) { java_error(env, r, "resolve SDK ABI"); return false; }
    jobject global_loader = env->NewGlobalRef(loader);
    jclass global_bridge = global_loader ? (jclass)env->NewGlobalRef(bridge) : nullptr;
    jclass global_backup = global_bridge ? (jclass)env->NewGlobalRef(backup) : nullptr;
    if (!global_loader || !global_bridge || !global_backup) {
        if (global_loader) env->DeleteGlobalRef(global_loader);
        if (global_bridge) env->DeleteGlobalRef(global_bridge);
        if (global_backup) env->DeleteGlobalRef(global_backup);
        java_error(env, r, "retain Hook SDK"); return false;
    }
    sdk_loader = global_loader;
    bridge_class = global_bridge;
    backup_class = global_backup;
    resolve_replacement = resolve;
    return true;
}
void info(ij2art_rsp& r, const DexStore::Entry& e) {
    r.retval = e.info.id;
    r.len = sizeof(e.info);
    memcpy(r.data, &e.info, sizeof(e.info));
}
LoadedDex* dex_loader(uint64_t id) {
    for (auto& d : loaded) if (id && d.id == id) return &d;
    return nullptr;
}
std::string art_build_id() {
    std::string result;
    dl_iterate_phdr([](dl_phdr_info* module, size_t, void* out) {
        const char* name = strrchr(module->dlpi_name, '/');
        if (strcmp(name ? name + 1 : module->dlpi_name, "libart.so")) return 0;
        for (size_t n = 0; n < module->dlpi_phnum; ++n) {
            const auto& ph = module->dlpi_phdr[n];
            if (ph.p_type != PT_NOTE) continue;
            auto* p = reinterpret_cast<const uint8_t*>(module->dlpi_addr + ph.p_vaddr);
            size_t remaining = ph.p_memsz;
            while (remaining >= sizeof(Elf64_Nhdr)) {
                Elf64_Nhdr note{}; memcpy(&note, p, sizeof(note));
                uint64_t names = (uint64_t(note.n_namesz) + 3) & ~uint64_t(3);
                uint64_t desc = (uint64_t(note.n_descsz) + 3) & ~uint64_t(3);
                uint64_t total = sizeof(note) + names + desc;
                if (total > remaining) break;
                if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4 &&
                    !memcmp(p + sizeof(note), "GNU", 4) && note.n_descsz <= 64) {
                    auto& id = *static_cast<std::string*>(out);
                    const uint8_t* bytes = p + sizeof(note) + names;
                    for (size_t k = 0; k < note.n_descsz; ++k) {
                        const char* hex = "0123456789abcdef";
                        id += hex[bytes[k] >> 4]; id += hex[bytes[k] & 15];
                    }
                    return 1;
                }
                p += total; remaining -= total;
            }
        }
        return 1;
    }, &result);
    return result;
}
int commit(DexStore::Entry& e, ij2art_rsp& r) {
    if (e.info.state == IJ2ART_DEX_READY) { info(r, e); return 0; }
    if (e.info.state == IJ2ART_DEX_FAILED) return message(r, e.info.error, e.failure);
    int rc = store().validate(e);
    if (rc) return message(r, rc, "DEX is incomplete, corrupt or not a supported standalone dex (035/037-040)");
    if (!attach(r)) return r.status;
    JNIEnv* env = worker_env;
    if (env->PushLocalFrame(64) != JNI_OK) return java_error(env, r, "DEX local frame");
    if (!ensure_sdk(env, r)) { env->PopLocalFrame(nullptr); return r.status; }
    jobject bytes = nullptr;
    jobject loader = make_loader(env, e.bytes.data(), e.bytes.size(), sdk_loader, bytes);
    LoadedDex* slot = nullptr;
    for (auto& d : loaded) if (!d.id) { slot = &d; break; }
    if (loader && slot && !env->ExceptionCheck()) {
        slot->loader = env->NewGlobalRef(loader);
        slot->bytes = slot->loader ? env->NewGlobalRef(bytes) : nullptr;
        if (slot->loader && slot->bytes && !env->ExceptionCheck()) {
            slot->id = e.info.id;
            e.info.state = IJ2ART_DEX_READY;
            std::vector<uint8_t>().swap(e.bytes);
            info(r, e);
        } else {
            if (slot->loader) env->DeleteGlobalRef(slot->loader);
            if (slot->bytes) env->DeleteGlobalRef(slot->bytes);
            *slot = {};
            java_error(env, r, "retain DEX loader");
        }
    } else java_error(env, r, "construct DEX loader");
    if (r.status) store().fail(e, r.status, std::string((char*)r.data, r.len));
    env->PopLocalFrame(nullptr);
    return r.status;
}
} // namespace

// art.cpp internals that are exposed to replace.cpp through artint; both sides run only on
// the control worker.
namespace ij2art::artint {
int message(ij2art_rsp& r, int error, const std::string& text) { return ::message(r, error, text); }
int java_error(JNIEnv* env, ij2art_rsp& r, const char* op, int code) {
    return ::java_error(env, r, op, code);
}
bool attach(ij2art_rsp& r) { return ::attach(r); }
JNIEnv* worker_env() { return ::worker_env; }
jobject app_loader() { return ::ready_loader; }
bool ensure_sdk(JNIEnv* env, ij2art_rsp& r) { return ::ensure_sdk(env, r); }
DexStore& dex_store() { return ::store(); }
jobject dex_loader_for(uint64_t id) {
    if (LoadedDex* d = ::dex_loader(id)) return d->loader;
    return nullptr;
}
void dex_ref_hooks(uint64_t id, int delta) {
    if (DexStore::Entry* e = ::store().find(id)) {
        int next = int(e->info.hook_refs) + delta;
        e->info.hook_refs = next > 0 ? uint32_t(next) : 0;
    }
}
std::string libart_build_id() { return ::art_build_id(); }
jclass sdk_bridge() { return ::bridge_class; }
jclass sdk_backup() { return ::backup_class; }
jobject sdk_class_loader() { return ::sdk_loader; }
} // namespace ij2art::artint

namespace {
// All hook commands are routed to the replace.cpp backend; when the adapter is not ready, the
// backend returns UNSUPPORTED_ART.
void route_hook(const ij2art_cmd& c, ij2art_rsp& r) {
    switch (c.type) {
    case IJ2ART_CMD_HOOK_INIT: ij2art::replace::init(c, r); break;
    case IJ2ART_CMD_HOOK_ADD: ij2art::replace::add(c, r); break;
    case IJ2ART_CMD_HOOK_UPDATE: ij2art::replace::update(c, r); break;
    case IJ2ART_CMD_HOOK_DEL: ij2art::replace::del(c, r); break;
    case IJ2ART_CMD_HOOK_LIST: ij2art::replace::list(r); break;
    case IJ2ART_CMD_HOOK_QUERY: ij2art::replace::query(c, r); break;
    }
}
} // namespace

extern "C" bool ij2art_runtime_ready(JNIEnv* env, jobject app_loader) {
    if (!env || !app_loader || env->ExceptionCheck()) return false;
    JavaVM* vm = nullptr;
    if (env->GetJavaVM(&vm) != JNI_OK) return false;
    jclass cls = env->FindClass("java/lang/ClassLoader");
    if (!cls) return false;
    bool valid = env->IsInstanceOf(app_loader, cls);
    env->DeleteLocalRef(cls);
    if (!valid) return false;
    jobject retained = env->NewGlobalRef(app_loader);
    if (!retained) return false;
    pthread_mutex_lock(&ready_mutex);
    bool accepted = !closed && (!ready_vm || (ready_vm == vm && env->IsSameObject(ready_loader, app_loader)));
    if (accepted && !ready_vm) { ready_vm = vm; ready_loader = retained; retained = nullptr; }
    pthread_mutex_unlock(&ready_mutex);
    if (retained) env->DeleteGlobalRef(retained);
    return accepted;
}

void ij2art_art_tick() {
    store().expire(now_ms());
    ij2art::replace::collect();
}

bool ij2art_art_command(const ij2art_cmd& c, ij2art_rsp& r) {
    ij2art::replace::collect();
    if (ij2art::java_calls::command(c, r)) return true;
    switch (c.type) {
    case IJ2ART_CMD_DEX_BEGIN: {
        DexStore::Entry* e = nullptr;
        int rc = store().begin(c.args[0], c.len, now_ms(), e);
        if (rc) message(r, rc, "invalid/reused upload nonce, DEX size or resource limit");
        else info(r, *e);
        break;
    }
    case IJ2ART_CMD_DEX_CHUNK:
    case IJ2ART_CMD_DEX_COMMIT:
    case IJ2ART_CMD_DEX_QUERY:
    case IJ2ART_CMD_DEX_DROP: {
        auto* e = c.type == IJ2ART_CMD_DEX_QUERY && !c.addr ? store().by_nonce(c.args[0]) : store().find(c.addr);
        if (!e) { message(r, IJ2ART_E_NOT_FOUND, "unknown dex_id/upload nonce in this process"); break; }
        if (c.type == IJ2ART_CMD_DEX_CHUNK) {
            int rc = c.len > IJ2ART_CMD_DATA_MAX ? IJ2ART_E_INVALID :
                store().chunk(*e, c.args[0], c.data, c.len, now_ms());
            if (rc) message(r, rc, "invalid chunk bounds, offset, state or conflicting retry");
            else info(r, *e);
        } else if (c.type == IJ2ART_CMD_DEX_COMMIT) commit(*e, r);
        else if (c.type == IJ2ART_CMD_DEX_QUERY) info(r, *e);
        else {
            uint64_t id = e->info.id;
            if (ij2art::java_calls::references(id, r)) break;
            int rc = store().drop(id);
            if (rc) message(r, rc, "DEX is still referenced by a Hook");
            else if (auto* d = dex_loader(id)) {
                worker_env->DeleteGlobalRef(d->loader);
                worker_env->DeleteGlobalRef(d->bytes);
                *d = {};
            }
        }
        break;
    }
    case IJ2ART_CMD_DEX_LIST:
        for (const auto& e : store().entries()) if (e.info.id) {
            // 16 slots x 48 bytes is far below the capacity; this guards against the same kind
            // of cumulative overflow as R4 and against the limit being raised in the future.
            if (r.len > IJ2ART_RSP_DATA_MAX - sizeof(e.info)) { r.flags |= 1; break; }
            memcpy(r.data + r.len, &e.info, sizeof(e.info)); r.len += sizeof(e.info);
        }
        break;
    case IJ2ART_CMD_HOOK_INIT:
    case IJ2ART_CMD_HOOK_ADD:
    case IJ2ART_CMD_HOOK_UPDATE:
    case IJ2ART_CMD_HOOK_LIST:
    case IJ2ART_CMD_HOOK_QUERY:
    case IJ2ART_CMD_HOOK_DEL: route_hook(c, r); break;
    default: return false;
    }
    return true;
}

bool ij2art_art_shutdown(ij2art_rsp& r) {
    if (!ij2art::java_calls::shutdown(r)) return false;
    // Close replacement admission, never restore native flags/entrypoints. Only
    // accepted handlers drain; ongoing original forwarding must not starve shutdown.
    bool retain_sdk = false;
    if (!ij2art::replace::shutdown_all(retain_sdk)) {
        message(r, IJ2ART_E_BUSY, "Hook invocations are still draining; retry shutdown");
        return false;
    }
    // A readiness signal may arrive without a prior JNI RPC; attach before releasing its global ref.
    pthread_mutex_lock(&ready_mutex);
    bool need_attach = ready_vm != nullptr;
    pthread_mutex_unlock(&ready_mutex);
    if (need_attach && !attach(r)) return false;
    pthread_mutex_lock(&ready_mutex);
    // Recheck under the same lock used by readiness publication.
    if (ready_vm && !worker_env) {
        pthread_mutex_unlock(&ready_mutex);
        message(r, IJ2ART_E_NOT_READY, "runtime readiness arrived during shutdown; retry shutdown");
        return false;
    }
    closed = true;
    if (ready_loader) { worker_env->DeleteGlobalRef(ready_loader); ready_loader = nullptr; }
    ready_vm = nullptr;
    pthread_mutex_unlock(&ready_mutex);
    // Logical disable retains JNI forwarding for the remainder of the process.
    // Keep SDK/DEX roots AND their accounting. Zero handler tickets is not proof
    // that ART's outer JNI frames have gone away and does not permit dlclose.
    ij2art::java_calls::release();
    if (!retain_sdk) {
        for (auto& d : loaded) if (d.id) {
            worker_env->DeleteGlobalRef(d.loader); worker_env->DeleteGlobalRef(d.bytes); d = {};
        }
        if (bridge_class) { worker_env->DeleteGlobalRef(bridge_class); bridge_class = nullptr; }
        if (backup_class) { worker_env->DeleteGlobalRef(backup_class); backup_class = nullptr; }
        if (sdk_loader) { worker_env->DeleteGlobalRef(sdk_loader); sdk_loader = nullptr; }
        for (const auto& e : store().entries()) if (e.info.id) store().drop(e.info.id);
    }
    if (worker_vm) { worker_vm->DetachCurrentThread(); worker_vm = nullptr; worker_env = nullptr; }
    return true;
}
