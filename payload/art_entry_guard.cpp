#include "art_entry_guard.h"
#include "inline_hook.h"
#include "jni_abi_constants.h"
#include "../common/art_proto.h"
#include <atomic>
#include <cstring>
#include <cstdio>

namespace ij2art::entry_guard {
namespace {
// Append-only, single writer. Lookup runs in ART, possibly with ART locks held:
// no allocation, JNI, ART calls, mutexes or access to the method's contents.
// Four times maximum occupancy bounds probes even when every slot is used.
constexpr size_t kCapacity = IJ2ART_JNI_SLOTS * 8;
static_assert((kCapacity & (kCapacity - 1)) == 0);
struct Entry {
    std::atomic<uintptr_t> method{0};
    const void* code = nullptr;
    // Only targets have a dispatch entry. Native target/backup pairs share
    // their original identity; the backup owns the live JNI binding.
    const void* dispatch = nullptr;
    void* native_backup = nullptr;
    void* native_identity = nullptr;
};
Entry entries[kCapacity];
bool installed;
const art_profile::Profile* active_profile;
size_t bucket(uintptr_t method) {
    return ((method >> 5) * 11400714819323198485ull) & (kCapacity - 1);
}
const Entry* lookup(void* method) {
    uintptr_t key = reinterpret_cast<uintptr_t>(method);
    for (size_t i = bucket(key); ; i = (i + 1) & (kCapacity - 1)) {
        uintptr_t found = entries[i].method.load(std::memory_order_acquire);
        if (!found) return nullptr;
        if (found == key) return &entries[i];
    }
}
const void* selected(void* method) {
    const Entry* entry = lookup(method);
    return entry ? entry->code : nullptr;
}
void publish(void* method, const void* code, const void* dispatch,
             void* native_backup, void* native_identity) {
    uintptr_t key = reinterpret_cast<uintptr_t>(method);
    for (size_t i = bucket(key); ; i = (i + 1) & (kCapacity - 1)) {
        if (entries[i].method.load(std::memory_order_relaxed)) continue;
        entries[i].code = code;
        entries[i].dispatch = dispatch;
        entries[i].native_backup = native_backup;
        entries[i].native_identity = native_identity;
        entries[i].method.store(key, std::memory_order_release);
        return;
    }
}

enum Point { Optimized, Invoke, Update, UpdateImpl, NativeUpdate, Reinitialize, Stubs,
             NativeBinding, NativeUnregister, Initialize, Count };
void* originals[Count]{};
void* handles[Count]{};
template<class Fn> Fn original(Point point) {
    // ShadowHook publishes the trampoline before making the patch visible.
    return reinterpret_cast<Fn>(__atomic_load_n(&originals[point], __ATOMIC_ACQUIRE));
}
using Select = const void* (*)(void*);
using SelectMember = const void* (*)(void*, void*);
using Write = void (*)(void*, const void*);
using WriteMember = void (*)(void*, void*, const void*);
using Reset = void (*)(void*, void*);
void write_pinned(void* instrumentation, void* method, const void* code) {
    // Retain ART's own entry-write bookkeeping: newer builds expose a separate
    // helper; Android 14/15 keep it inside UpdateMethodsCode.
    if (originals[Update]) original<Write>(Update)(method, code);
    else original<WriteMember>(UpdateImpl)(instrumentation, method, code);
}
const void* optimized(void* method) {
    if (const void* code = selected(method)) return code;
    return original<Select>(Optimized)(method);
}
const void* invoke(void* instrumentation, void* method) {
    if (const void* code = selected(method)) return code;
    return original<SelectMember>(Invoke)(instrumentation, method);
}
void update(void* method, const void* requested) {
    const void* code = selected(method);
    original<Write>(Update)(method, code ? code : requested);
}
void update_impl(void* instrumentation, void* method, const void* requested) {
    const void* code = selected(method);
    original<WriteMember>(UpdateImpl)(instrumentation, method, code ? code : requested);
}
void native_update(void* instrumentation, void* method, const void* requested) {
    const void* code = selected(method);
    original<WriteMember>(NativeUpdate)(instrumentation, method, code ? code : requested);
}
void reinitialize(void* instrumentation, void* method) {
    if (const void* code = selected(method)) return write_pinned(instrumentation, method, code);
    original<Reset>(Reinitialize)(instrumentation, method);
}
void stubs(void* instrumentation, void* method) {
    if (const void* code = selected(method)) return write_pinned(instrumentation, method, code);
    original<Reset>(Stubs)(instrumentation, method);
}
void initialize(void* instrumentation, void* method, const void* requested) {
    if (const void* code = selected(method)) return write_pinned(instrumentation, method, code);
    original<WriteMember>(Initialize)(instrumentation, method, requested);
}

using Bind = void (*)(void*, void*, const void*, void**);
void native_binding(void* callbacks, void* method, const void* requested, void** result) {
    const Entry* entry = lookup(method);
    // RegisterNatives must not turn a converted Java method's CodeItem into a
    // JNI pointer. UnregisterNatives visits these synthetic natives too.
    if (entry && entry->dispatch && !entry->native_backup) {
        *result = const_cast<void*>(entry->dispatch);
        return;
    }
    // Lazy resolution runs on the backup. ART/JVMTI binding callbacks must see
    // the application's method identity, and may replace the requested fn.
    original<Bind>(NativeBinding)(callbacks,
        entry && entry->native_identity ? entry->native_identity : method, requested, result);
    // A callback can suspend. Recheck AFTER it returns: installation may have
    // published the pair while this registration was inside the callback.
    entry = lookup(method);
    if (!entry || !entry->dispatch) return;
    if (entry->native_backup) {
        auto** data = reinterpret_cast<void**>(static_cast<unsigned char*>(entry->native_backup) + active_profile->method.data);
        __atomic_store_n(data, *result, __ATOMIC_RELEASE);
    }
    // ClassLinker::RegisterNative stores this result directly into data_. Pin
    // the dispatch BEFORE that write, never repair an exposed original entry.
    *result = const_cast<void*>(entry->dispatch);
}
void native_unregister(void* linker, void* self, void* method) {
    if (const Entry* entry = lookup(method)) {
        if (!entry->native_backup) return; // converted managed target/backup
        method = entry->native_backup;
    }
    using Unregister = void (*)(void*, void*, void*);
    // ART installs its dlsym stub on the backup. callOriginal then resolves by
    // the copied declaring class/name/signature, or throws UnsatisfiedLinkError.
    original<Unregister>(NativeUnregister)(linker, self, method);
}

// The ordered proxy signatures are shared; each profile supplies its audited
// subset of writers, including functions into which a helper was inlined.
using art_profile::Symbol;
struct Guard { Symbol symbol; void* proxy; };
const Guard guards[Count] = {
    {Symbol::optimized, reinterpret_cast<void*>(optimized)},
    {Symbol::invoke, reinterpret_cast<void*>(invoke)},
    {Symbol::update, reinterpret_cast<void*>(update)},
    {Symbol::update_impl, reinterpret_cast<void*>(update_impl)},
    {Symbol::native_update, reinterpret_cast<void*>(native_update)},
    {Symbol::reinitialize, reinterpret_cast<void*>(reinitialize)},
    {Symbol::stubs, reinterpret_cast<void*>(stubs)},
    {Symbol::native_binding, reinterpret_cast<void*>(native_binding)},
    {Symbol::native_unregister, reinterpret_cast<void*>(native_unregister)},
    {Symbol::initialize, reinterpret_cast<void*>(initialize)},
};
}
bool install(uintptr_t base, const art_profile::Profile& profile, ij2art_rsp& r) {
    if (installed) return active_profile == &profile;
    active_profile = &profile;
    // Validate every still-unpatched site first. Partial installation is safe:
    // no registry entries exist until all hooks succeed, so proxies pass through.
    // Keep partial hooks (and their original slots) alive for retry; unpatching
    // on failure would race an already-entered proxy.
    for (size_t i = 0; i < Count; ++i) {
        const auto& site = profile.site(guards[i].symbol);
        if (!site.rva) continue;
        if (!handles[i] && memcmp(reinterpret_cast<void*>(base + site.rva),
                                 site.prologue, sizeof(site.prologue))) {
            r.status = IJ2ART_E_UNSUPPORTED_ART;
            r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data),
                             "ART entry guard prologue mismatch at +0x%lx", site.rva);
            return false;
        }
    }
    for (size_t i = 0; i < Count; ++i) {
        const auto& site = profile.site(guards[i].symbol);
        if (!site.rva) continue;
        if (!ij2art_inline_permanent(reinterpret_cast<void*>(base + site.rva),
                                       guards[i].proxy, &originals[i], &handles[i], r)) return false;
    }
    installed = true;
    return true;
}
bool ready() { return installed; }
size_t count() {
    size_t result = 0;
    for (void* handle : handles) if (handle) ++result;
    return result;
}
void protect(void* target, void* backup, const void* generic, const void* backup_code,
             const void* dispatch, bool native_target) {
    publish(target, generic, dispatch, native_target ? backup : nullptr, native_target ? target : nullptr);
    publish(backup, backup_code, nullptr, native_target ? backup : nullptr, native_target ? target : nullptr);
}
}
