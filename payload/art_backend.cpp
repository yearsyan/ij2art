#include "art_backend.h"
#include "art_admission.h"
#include "art_entry_guard.h"
#include "../common/art_proto.h"
#include <cstdio>
#include <unistd.h>

namespace ij2art::art_backend {
namespace {
using art_profile::Symbol;
const art_profile::Profile* active;
uintptr_t art_base;
admission::Api api;
template<class T> T fn(Symbol symbol) { return active->at<T>(art_base, symbol); }
struct Pause {
    alignas(8) unsigned char gc[32]{};
    unsigned char suspended{};
    Pause() {
        fn<void(*)(void*, void*, int, int)>(Symbol::gc_enter)(gc, fn<void*(*)()>(Symbol::current)(), 8, 9);
        fn<void(*)(void*, const char*, bool)>(Symbol::suspend)(&suspended, "ij2art hook", false);
    }
    ~Pause() {
        fn<void(*)(void*)>(Symbol::resume)(&suspended);
        fn<void(*)(void*)>(Symbol::gc_exit)(gc);
    }
};
template<class T> void write(void* method, size_t offset, T value) {
    memcpy(static_cast<unsigned char*>(method) + offset, &value, sizeof(value));
}
}
bool ready() { return active && entry_guard::ready(); }
const art_profile::Profile* profile() { return active; }
size_t guard_count() { return entry_guard::count(); }
bool initialize(const art_profile::Profile& p, uintptr_t base, const uint64_t* symbols,
                size_t n, ij2art_rsp& r) {
    if (ready()) return active == &p && art_base == base;
    char error[512]{};
    if ((n != 0 && n != 8) || p.layout.gc_section_size > sizeof(Pause::gc)) {
        snprintf(error, sizeof(error), "ART backend initialization layout/argument mismatch");
    } else {
        for (size_t i = 0; i < n; ++i) if (symbols[i] != base + p.sites[i].rva) {
            snprintf(error, sizeof(error), "ART backend symbol mismatch: %s", p.sites[i].name);
            break;
        }
    }
    if (*error || !art_profile::validate(p, base, error, sizeof(error))) {
        r.status = IJ2ART_E_UNSUPPORTED_ART;
        r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data), "%s", error);
        return false;
    }
    if (!api.bind(base)) {
        r.status = IJ2ART_E_UNSUPPORTED_ART;
        r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data), "ART admission layout unavailable");
        return false;
    }
    if (!entry_guard::install(base, p, r)) return false;
    active = &p;
    art_base = base;
    return true;
}
Result install(void* target, void* backup, void* dispatch, void (*publish)(void*), void* context) {
    if (!ready()) return {IJ2ART_E_UNSUPPORTED_ART, "ART backend is not initialized"};
    void* self = fn<void*(*)()>(Symbol::current)();
    void* interpreter = fn<void*>(Symbol::interpreter);
    void* generic = fn<void*>(Symbol::generic);
    api.prepare(self);
    Result result;
    for (int attempt = 0; ; ++attempt) {
        {
            Pause pause;
            result = api.check(self, target, backup, interpreter);
            if (result) {
                const auto& m = active->method;
                uint32_t flags = active->read<uint32_t>(target, m.flags);
                bool native_target = flags & m.native_flag;
                api.retire(self, target, backup);
                fn<void(*)(void*, void*, size_t)>(Symbol::copy)(backup, target, sizeof(void*));
                uint32_t copied = active->read<uint32_t>(backup, m.flags);
                write(backup, m.flags, (copied | m.no_compile) &
                    ~(m.precompiled | m.nterp_invoke | m.nterp_entry_or_critical));
                // Synchronization bits remain on both methods. A native backup
                // uses generic JNI even when retirement freed its old JNI stub.
                void* backup_code = native_target ? generic : interpreter;
                write(backup, m.quick, backup_code);
                write(target, m.data, dispatch);
                write(target, m.flags, (flags | m.no_compile | m.native_flag) &
                    ~(m.precompiled | m.nterp_invoke | m.nterp_entry_or_critical | m.skip_checks_or_fast));
                write(target, m.quick, generic);
                entry_guard::protect(target, backup, generic, backup_code, dispatch, native_target);
                publish(context);
            }
        }
        if (result || !result.retry || attempt == 20) return result;
        usleep(10000); // outside the GC critical section; let compiler tasks finish
    }
}
}
