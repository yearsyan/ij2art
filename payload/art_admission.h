// Admission and retirement for audited ART backends. Layouts and symbols come
// from exact-build profiles; the two code-cache locking protocols stay explicit.
#pragma once
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include "../common/art_proto.h"
#include "art_backend.h"
#include "art_entry_guard.h"

namespace ij2art::admission {
template<class T> T read(const void* p, size_t offset) {
    T value;
    memcpy(&value, static_cast<const unsigned char*>(p) + offset, sizeof(value));
    return value;
}
using Result = art_backend::Result;
struct Api {
    const art_profile::Profile* profile = nullptr;
    uintptr_t art_base = 0;
    void** runtime = nullptr;
    void** thread_list_lock = nullptr;
    void (*lock)(void*, void*) = nullptr;
    bool (*try_lock)(void*, void*) = nullptr;
    void (*unlock)(void*, void*) = nullptr;
    void (*for_each)(void*, void (*)(void*, void*), void*) = nullptr;
    void (*visitor_init)(void*, void*, void*, int, bool) = nullptr;
    void (*walk)(void*, bool) = nullptr;
    void* (*method)(void*) = nullptr;
    bool (*jit_first_use)(void*) = nullptr;
    void** jit_lock = nullptr;
    void** jit_mutator_lock = nullptr;
    void** cha_lock = nullptr;
    void (*write_lock)(void*, void*) = nullptr;
    void (*write_unlock)(void*, void*) = nullptr;
    bool (*remove_method_locked)(void*, void*, bool) = nullptr;
    void (*erase_pointer_set)(void*, const void*) = nullptr;
    void (*erase_method_map)(void*, const void*) = nullptr;
    const void* (*zygote_code)(void*, void*, size_t) = nullptr;
    bool (*is_deoptimized)(void*, void*) = nullptr;
    bool (*outstanding)(void*) = nullptr;
    const void* (*oat_code)(void*, size_t) = nullptr;
    void* nterp = nullptr;
    // art_jni_dlsym_lookup_stub (RVA from this build's symbol table): data_ of a
    // declared native that has not been bound yet. A bound native holds the
    // registered JNI function there instead.
    void* jni_dlsym_stub = nullptr;
    void (*make_visible)(void*, void*, bool) = nullptr;

    // The exported StackVisitor ctor initializes 0x1f0 bytes; its dtor is trivial.
    // We replace only its VisitFrame vtable callback. No ART object is fabricated
    // for the target: the visitor operates on ART-owned suspended thread stacks.
    struct alignas(8) Visitor {
        unsigned char art[0x1f0];
        Api* api;
        void* target;
        bool found;
        static void destroy(void*) {}  // never called (placement storage)
        static bool visit(void* raw) {
            auto* v = static_cast<Visitor*>(raw);
            if (v->api->method(v) == v->target) v->found = true;
            return !v->found;
        }
    };
    struct Scan { Api* api; void* target; bool found = false; };
    static void scan_thread(void* thread, void* opaque) {
        auto* s = static_cast<Scan*>(opaque);
        if (s->found) return;
        Visitor v{};
        s->api->visitor_init(&v, thread, nullptr, /* include inlined */0, true);
        // Itanium ABI: complete dtor, deleting dtor, VisitFrame.
        static const uintptr_t table[] = {
            0, 0, reinterpret_cast<uintptr_t>(&Visitor::destroy),
            reinterpret_cast<uintptr_t>(&Visitor::destroy),
            reinterpret_cast<uintptr_t>(&Visitor::visit)};
        const uintptr_t* vptr = table + 2;
        memcpy(v.art, &vptr, sizeof(vptr));
        v.api = s->api; v.target = s->target; v.found = false;
        s->api->walk(&v, false);
        s->found = v.found;
    }
    bool bind(uintptr_t base) {
        art_base = base;
        profile = art_profile::from_base(base);
        if (!profile || profile->layout.visitor_size > sizeof(Visitor::art)) return false;
        runtime = profile->at<decltype(runtime)>(base, art_profile::Symbol::runtime);
        thread_list_lock = profile->at<decltype(thread_list_lock)>(base, art_profile::Symbol::thread_list_lock);
        lock = profile->at<decltype(lock)>(base, art_profile::Symbol::lock);
        try_lock = profile->at<decltype(try_lock)>(base, art_profile::Symbol::try_lock);
        unlock = profile->at<decltype(unlock)>(base, art_profile::Symbol::unlock);
        for_each = profile->at<decltype(for_each)>(base, art_profile::Symbol::for_each);
        visitor_init = profile->at<decltype(visitor_init)>(base, art_profile::Symbol::visitor_init);
        walk = profile->at<decltype(walk)>(base, art_profile::Symbol::walk);
        method = profile->at<decltype(method)>(base, art_profile::Symbol::method);
        jit_first_use = profile->at<decltype(jit_first_use)>(base, art_profile::Symbol::jit_first_use);
        jit_lock = profile->at<decltype(jit_lock)>(base, art_profile::Symbol::jit_lock);
        jit_mutator_lock = profile->at<decltype(jit_mutator_lock)>(base, art_profile::Symbol::jit_mutator_lock);
        cha_lock = profile->at<decltype(cha_lock)>(base, art_profile::Symbol::cha_lock);
        write_lock = profile->at<decltype(write_lock)>(base, art_profile::Symbol::write_lock);
        write_unlock = profile->at<decltype(write_unlock)>(base, art_profile::Symbol::write_unlock);
        remove_method_locked = profile->at<decltype(remove_method_locked)>(base, art_profile::Symbol::remove_method_locked);
        erase_pointer_set = profile->at<decltype(erase_pointer_set)>(base, art_profile::Symbol::erase_pointer_set);
        erase_method_map = profile->at<decltype(erase_method_map)>(base, art_profile::Symbol::erase_method_map);
        zygote_code = profile->at<decltype(zygote_code)>(base, art_profile::Symbol::zygote_code);
        is_deoptimized = profile->at<decltype(is_deoptimized)>(base, art_profile::Symbol::is_deoptimized);
        outstanding = profile->at<decltype(outstanding)>(base, art_profile::Symbol::outstanding);
        oat_code = profile->at<decltype(oat_code)>(base, art_profile::Symbol::oat_code);
        nterp = profile->at<decltype(nterp)>(base, art_profile::Symbol::nterp);
        jni_dlsym_stub = profile->at<decltype(jni_dlsym_stub)>(base, art_profile::Symbol::jni_dlsym_stub);
        make_visible = profile->at<decltype(make_visible)>(base, art_profile::Symbol::make_visible);
        return true;
    }
    void lock_code(void* self) { if (jit_mutator_lock) write_lock(*jit_mutator_lock, self); }
    void unlock_code(void* self) { if (jit_mutator_lock) write_unlock(*jit_mutator_lock, self); }

    static unsigned char* bytes(void* p, size_t offset) {
        return static_cast<unsigned char*>(p) + offset;
    }
    // Read ART's libc++ tree without constructing NDK STL objects over it.
    // Tree: begin/root/size; node: left/right/parent/color/key/value.
    template<class Fn> static void for_codes(void* cache, Fn fn) {
        void* end = bytes(cache, 0x318);
        for (void* node = read<void*>(cache, 0x310); node != end;) {
            fn(read<void*>(node, 0x28), read<const void*>(node, 0x20));
            if (void* right = read<void*>(node, 8)) {
                node = right;
                while (void* left = read<void*>(node, 0)) node = left;
            } else {
                void* parent = read<void*>(node, 16);
                while (read<void*>(parent, 0) != node) {
                    node = parent;
                    parent = read<void*>(node, 16);
                }
                node = parent;
            }
        }
    }

    // Called only after ALL checks succeed, still under STW + GC exclusion.
    // Unlike RemoveMethod(true) alone, remove zombie and CHA references before
    // ART frees/reuses headers. No Java calls, suspension or managed allocation.
    void retire(void* self, void* target, void* backup) {
        void* cache = read<void*>(*runtime, profile->layout.runtime_cache);
        if (!cache) return;
        lock(*jit_lock, self);
        lock_code(self);
        for_codes(cache, [&](void* owner, const void* code) {
            if (owner != target && owner != backup) return;
            if (profile->family == art_profile::Family::ZombieCode) {
                erase_pointer_set(bytes(cache, profile->layout.cache_zombies), &code);
                erase_pointer_set(bytes(cache, profile->layout.cache_osr_zombies), &code);
            }
        });
        erase_method_map(bytes(cache, profile->layout.cache_saved), &target); // saved pre-JIT entries
        erase_method_map(bytes(cache, profile->layout.cache_saved), &backup);
        unlock_code(self);

        // CHA and jit_mutator have the same lock level: never nest them.
        lock(*cha_lock, self);
        void* cha = read<void*>(read<void*>(*runtime, profile->layout.runtime_linker), profile->layout.linker_cha);
        // CHA unordered-map nodes hold a vector<pair<method, header>>. Compact
        // trivial pairs in place, preserving ART's allocator and vector capacity.
        // Empty dependency lists are legal (GetDependents returns that list).
        for (void* node = read<void*>(cha, 0x10); node; node = read<void*>(node, 0)) {
            auto* out = read<unsigned char*>(node, 0x18);
            auto* end = read<unsigned char*>(node, 0x20);
            for (auto* pair = out; pair != end; pair += 16) {
                void* owner = read<void*>(pair, 0);
                if (owner != target && owner != backup) {
                    if (out != pair) memcpy(out, pair, 16);
                    out += 16;
                }
            }
            memcpy(bytes(node, 0x20), &out, sizeof(out));
        }
        unlock(*cha_lock, self);
        // Removes every private tier/OSR version, reverse map, OSR dispatch map
        // and profiling lookup. FreeLocked also removes native debug info.
        remove_method_locked(cache, target, true);
        remove_method_locked(cache, backup, true);
        unlock(*jit_lock, self);
    }

    // Native worker, no ART locks held. Finish pending initialization publication
    // BEFORE STW so its callbacks can run and cannot later rewrite the backup.
    void prepare(void* self) {
        if (*runtime) make_visible(read<void*>(*runtime, profile->layout.runtime_linker), self, true);
    }

    // Caller owns the GC critical section and exclusive mutator lock throughout
    // check -> conversion -> slot publication. Never wait for frames/tasks here.
    Result check(void* self, void* target, void* backup, const void* interpreter) {
        void* rt = *runtime;
        if (!rt) return {IJ2ART_E_UNSUPPORTED_ART, "ART runtime unavailable"};
        void* instr = profile->instrumentation(rt);
        if (!instr || read<uint32_t>(instr, 4) != 0 ||
            is_deoptimized(instr, target) || is_deoptimized(instr, backup))
            return {IJ2ART_E_UNSUPPORTED_ART, "active instrumentation or target deoptimization conflicts with method conversion"};
        void* jit = read<void*>(rt, profile->layout.runtime_jit);
        // Runtime retains its code cache separately; absence of Jit does not
        // imply absence of old code. Validate/retire the cache below either way.
        void* cache = read<void*>(rt, profile->layout.runtime_cache);
        if (jit && read<void*>(jit, 8) != cache)
            return {IJ2ART_E_UNSUPPORTED_ART, "JIT code cache ownership mismatch"};
        if (jit && (read<void*>(jit, 0x18) ||
                    read<uint8_t>(read<void*>(jit, 0x10), 0) != 0)) {
            if (jit_first_use(jit)) return {IJ2ART_E_UNSUPPORTED_ART, "synchronous JIT-at-first-use is unsupported"};
            void* pool = read<void*>(jit, 0x18);
            if (!pool) return {IJ2ART_E_BUSY, "JIT worker pool is not ready", true};
            auto* mutex = static_cast<unsigned char*>(pool) + 0x20;
            if (!try_lock(mutex, self)) return {IJ2ART_E_BUSY, "JIT task queue is busy; retry installation", true};
            uintptr_t begin = read<uintptr_t>(pool, profile->layout.pool_threads), end = read<uintptr_t>(pool, profile->layout.pool_threads + 8);
            bool idle = read<uint8_t>(pool, profile->layout.pool_started) == 1 &&
                        read<uint8_t>(pool, profile->layout.pool_started + 1) == 0 && end >= begin &&
                        (end - begin) % sizeof(void*) == 0 &&
                        read<size_t>(pool, profile->layout.pool_waiting) == (end - begin) / sizeof(void*) &&
                        !outstanding(pool);
            unlock(mutex, self);
            if (!idle) return {IJ2ART_E_BUSY, "JIT compilation or queued work is active; retry installation", true};
            // New pool tasks acquire shared mutator access before inspecting
            // methods. STW prevents them starting after this idle observation.
        }
        Scan scan{this, target};
        lock(*thread_list_lock, self);
        for_each(read<void*>(rt, profile->layout.runtime_threads), &scan_thread, &scan);
        if (!scan.found) {
            scan.target = backup;
            for_each(read<void*>(rt, profile->layout.runtime_threads), &scan_thread, &scan);
        }
        unlock(*thread_list_lock, self);
        if (scan.found) return {IJ2ART_E_BUSY, "target or backup has active managed frames; retry after they exit"};
        for (void* method_ptr : {target, backup}) {
            uint32_t flags = read<uint32_t>(method_ptr, profile->method.flags);
            if (flags & 0x100u) {
                // Declared native target (the SDK backup is always managed).
                // Only bound natives: data_ must be the registered JNI function,
                // not the lazy dlsym stub. Critical natives use a raw-argument
                // ABI without JNIEnv. Normal synchronized JNI is supported:
                // GenericJni owns the monitor on both target and native backup.
                void* fn = read<void*>(method_ptr, profile->method.data);
                if (!fn || fn == jni_dlsym_stub)
                    return {IJ2ART_E_STATE, "native method has no registered JNI entry; call it once or RegisterNatives first"};
                if (flags & (0x00100000u | 0x80000000u))
                    return {IJ2ART_E_UNSUPPORTED_ART, "critical or intrinsic native methods are not eligible"};
                if ((flags & 0x00080000u) && (flags & 0x00020020u))
                    return {IJ2ART_E_UNSUPPORTED_ART, "ART does not support synchronized FastNative methods"};
                const void* quick = read<void*>(method_ptr, profile->method.quick);
                // Bound natives run through a marshalling entry: the generic JNI
                // trampoline, or a signature-cached JNI stub in the private code
                // cache (installed once the method gets called). Both end up
                // calling data_ with the JNI convention, hold no per-method code
                // ownership, and every writer that publishes stub entries is
                // guarded. Interpreter/nterp entries make no sense for a native.
                if (!quick || quick == interpreter || quick == nterp)
                    return {IJ2ART_E_UNSUPPORTED_ART, "native method entry is not a JNI marshalling entry"};
                continue;  // native stubs use the JNI path; retirement still removes private JNI code
            }
            if (!read<void*>(method_ptr, profile->method.data)) return {IJ2ART_E_UNSUPPORTED_ART, "method has no managed code item"};
            // DeclaredSynchronized (0x20000) is retained. GenericJni in both
            // audited profiles tests both synchronization bits; managed backup bytecode
            // keeps its original monitor-enter/exit operations. The native-only
            // Synchronized bit (0x20) is still invalid on a managed method.
            if (flags & (0x80000000u | 0x01000000u | 0x100u | 0x400u | 0x20u))
                return {IJ2ART_E_UNSUPPORTED_ART, "method flags are not eligible for conversion"};
            auto klass = reinterpret_cast<void*>(uintptr_t(read<uint32_t>(method_ptr, profile->method.declaring_class)));
            if (!klass || (read<uint32_t>(klass, profile->layout.class_status) >> 28) != 15)
                return {IJ2ART_E_BUSY, "declaring class is not visibly initialized"};
            const void* oat = oat_code(method_ptr, 8);
            if (oat && !entry_guard::ready())
                return {IJ2ART_E_UNSUPPORTED_ART, "AOT entry protection is unavailable"};
            if (cache && zygote_code(bytes(cache, profile->layout.cache_zygote), method_ptr, 0))
                return {IJ2ART_E_UNSUPPORTED_ART, "shared zygote JIT publication is not yet supported"};
            const void* quick = read<void*>(method_ptr, profile->method.quick);
            bool known = quick == interpreter || quick == nterp || profile->is_pattern(art_base, quick) ||
                         (oat && quick == oat);
            if (cache) {
                lock(*jit_lock, self);
                bool collecting = read<uint8_t>(cache, profile->layout.cache_collecting) != 0;
                lock_code(self);
                for_codes(cache, [&](void* owner, const void* code) {
                    if (owner == method_ptr && code == quick) known = true;
                });
                unlock_code(self);
                unlock(*jit_lock, self);
                if (collecting) return {IJ2ART_E_BUSY, "JIT code collection is active; retry installation", true};
            }
            if (!known)
                return {IJ2ART_E_UNSUPPORTED_ART, "method entry is not a recognized interpreter, pattern stub, OAT or private JIT entry"};
        }
        return {};
    }
};
} // namespace ij2art::admission
