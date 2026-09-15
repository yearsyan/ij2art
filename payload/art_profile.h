#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ij2art::art_profile {
// Symbol signatures belong to the backend, not to an Android API-level guess.
enum class Symbol : size_t {
    suspend, resume, gc_enter, gc_exit, current, copy, generic, interpreter,
    runtime, thread_list_lock, lock, try_lock, unlock, for_each, visitor_init, walk,
    method, jit_first_use, jit_lock, jit_mutator_lock, cha_lock, write_lock, write_unlock,
    remove_method_locked, erase_pointer_set, erase_method_map, zygote_code, is_deoptimized,
    outstanding, oat_code, nterp, jni_dlsym_stub, make_visible,
    add_compile_task, collect_cache, add_method_callback, remove_method_callback,
    optimized, invoke, update, update_impl, native_update, reinitialize, stubs,
    native_binding, native_unregister, initialize,
    add_generic_task, insert_pointer_set, add_dependency, lookup_osr, maybe_invoke, outer_update, Count
};
struct Site {
    const char* name;
    uintptr_t rva;
    uint32_t prologue[4]; // zero for data symbols/absent optional functions
};
enum class Family { LockedCode, ZombieCode };
struct Layout {
    size_t runtime_threads, runtime_linker, runtime_jit, runtime_cache;
    size_t runtime_instrumentation, runtime_callbacks, runtime_debuggable;
    bool instrumentation_pointer;
    size_t linker_cha, class_status;
    size_t pool_started, pool_waiting, pool_threads;
    size_t cache_saved, cache_zygote, cache_collecting;
    size_t cache_zombies, cache_osr_zombies; // only the zombie-code backend
    size_t visitor_size, gc_section_size;
};
struct MethodLayout {
    size_t size = 32, declaring_class = 0, flags = 4, data = 16, quick = 24;
    uint32_t no_compile = 0x02000000, precompiled = 0x00800000;
    uint32_t nterp_invoke = 0x00200000, nterp_entry_or_critical = 0x00100000;
    uint32_t skip_checks_or_fast = 0x00080000, native_flag = 0x100;
};
struct Profile {
    const char* build_id;
    const char* name;
    Family family;
    Layout layout;
    MethodLayout method;
    const Site* sites;
    const uint32_t* patterns;
    size_t pattern_count;
    const Site& site(Symbol id) const { return sites[static_cast<size_t>(id)]; }
    template<class T> T at(uintptr_t base, Symbol id) const {
        uintptr_t rva = site(id).rva;
        return rva ? reinterpret_cast<T>(base + rva) : nullptr;
    }
    template<class T> T read(const void* object, size_t offset) const {
        T value; memcpy(&value, static_cast<const unsigned char*>(object) + offset, sizeof(value));
        return value;
    }
    void* instrumentation(void* runtime) const {
        return layout.instrumentation_pointer ? read<void*>(runtime, layout.runtime_instrumentation)
            : static_cast<unsigned char*>(runtime) + layout.runtime_instrumentation;
    }
    bool is_pattern(uintptr_t base, const void* entry) const {
        uintptr_t rva = reinterpret_cast<uintptr_t>(entry) - base;
        for (size_t i = 0; i < pattern_count; ++i) if (patterns[i] == rva) return true;
        return false;
    }
};
const Profile* find(const char* build_id);
// For isolated fixture processes and read-only runtime diagnostics.
const Profile* from_base(uintptr_t base);
// Resolve exported symbols first; exact-build RVA fallback covers hidden/LTO
// symbols. Validate the address and executable prologue before any mutation.
bool validate(const Profile&, uintptr_t base, char* error, size_t error_size);
}
