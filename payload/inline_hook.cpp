#include "inline_hook.h"
#include "loader.h"
#include "../third_party/shadowhook/include/shadowhook.h"
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

namespace {
struct Hook {
    ij2art_inline_info info{};
    void* stub = nullptr;
    void* original = nullptr;
    void* pins[3]{};
};
Hook hooks[IJ2ART_INLINE_SLOTS];
size_t count;

void message(ij2art_rsp& r, int code, const char* text) {
    r.status = code;
    r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data), "%s", text);
}
void backend_error(ij2art_rsp& r, int code) {
    r.status = IJ2ART_E_INLINE_BACKEND;
    r.retval = static_cast<uint64_t>(code);
    r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data),
                     "ShadowHook error=%d: %s", code, shadowhook_to_errmsg(code));
}
void record(ij2art_rsp& r, const Hook& h) {
    memcpy(r.data, &h.info, sizeof(h.info));
    r.len = sizeof(h.info);
    r.retval = h.info.id;
}

// The ring worker blocks signals. ShadowHook's guarded instruction reads/writes
// require synchronous SIGSEGV/SIGBUS delivery on this thread.
struct FaultSignals {
    sigset_t saved{};
    bool ok;
    FaultSignals() {
        sigset_t faults;
        sigemptyset(&faults);
        sigaddset(&faults, SIGSEGV);
        sigaddset(&faults, SIGBUS);
        ok = pthread_sigmask(SIG_UNBLOCK, &faults, &saved) == 0;
    }
    ~FaultSignals() { if (ok) pthread_sigmask(SIG_SETMASK, &saved, nullptr); }
};

bool mapped(uint64_t addr, size_t size, bool executable) {
    // A heap-backed original slot may carry an Android MTE/TBI data tag. maps
    // uses untagged addresses; keep the original pointer for the actual store.
    if (!executable) addr &= 0x00ffffffffffffffULL;
    if (!addr || addr > UINT64_MAX - size) return false;
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return false;
    char line[1024], perms[5];
    unsigned long start, end;
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) continue;
        if (start <= addr && addr + size <= end) {
            found = perms[0] == 'r' && (executable ? perms[2] == 'x'
                                                  : perms[1] == 'w' && perms[2] != 'x');
            break;
        }
    }
    fclose(f);
    return found;
}

int main_base(dl_phdr_info* info, size_t, void* out) {
    *static_cast<uintptr_t*>(out) = info->dlpi_addr;
    return 1;
}
bool pin(uint64_t addr, void*& handle, bool require_elf) {
    if (!require_elf) addr &= 0x00ffffffffffffffULL;
    Dl_info info{};
    if (!dladdr(reinterpret_cast<void*>(addr), &info)) return !require_elf;
    uintptr_t exe = 0;
    dl_iterate_phdr(main_base, &exe);
    if (reinterpret_cast<uintptr_t>(info.dli_fbase) == exe) return true;
    handle = dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD);
    if (handle) return true;
    // A library uploaded via `lib load` has no live path for the NOLOAD lookup;
    // the loader registry is its pin and refuses unload while a hook uses it.
    return ij2art_loader_owns_base(reinterpret_cast<uintptr_t>(info.dli_fbase));
}
void release_pins(Hook& h) {
    for (void*& handle : h.pins) {
        if (handle) dlclose(handle);
        handle = nullptr;
    }
}
bool initialize(ij2art_rsp& r) {
    int error = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
    if (error) { backend_error(r, error); return false; }
    return true;
}

void add(const ij2art_cmd& c, ij2art_rsp& r) {
    uint64_t target = c.addr, replacement = c.args[0], slot = c.args[1];
    if (target == replacement || (target & 3) || (replacement & 3) ||
        !mapped(target, 4, true) || !mapped(replacement, 4, true) ||
        (slot && ((slot & 7) || !mapped(slot, sizeof(void*), false)))) {
        return message(r, IJ2ART_E_INLINE_INVALID,
                       "require distinct aligned executable functions and an aligned writable non-executable original slot");
    }
    for (size_t i = 0; i < count; ++i) {
        const auto& old = hooks[i].info;
        if (old.state != IJ2ART_INLINE_REMOVED &&
            (old.target == target || (slot && (old.original_slot & 0x00ffffffffffffffULL) ==
                                              (slot & 0x00ffffffffffffffULL)))) {
            return message(r, IJ2ART_E_INLINE_STATE, "target or original slot already registered; use inline list/query");
        }
    }
    if (count == IJ2ART_INLINE_SLOTS)
        return message(r, IJ2ART_E_INLINE_LIMIT, "inline hook record limit reached");

    Hook& h = hooks[count];
    // Address-only upstream mode has no dlclose monitor. Keep the participating
    // ELFs loaded, even after removal, so an already-entered proxy stays mapped.
    if (!pin(target, h.pins[0], true) || !pin(replacement, h.pins[1], true) ||
        (slot && !pin(slot, h.pins[2], false))) {
        release_pins(h);
        return message(r, IJ2ART_E_INLINE_INVALID,
                       "cannot retain target/replacement ELF; functions must belong to loaded accessible ELFs");
    }
    if (!initialize(r)) { release_pins(h); return; }
    void** original = slot ? reinterpret_cast<void**>(slot) : &h.original;
    // Do not fill the proxy's original slot after this call: it can already be
    // executing by then. ShadowHook publishes this pointer before the patch.
    h.stub = shadowhook_hook_func_addr(reinterpret_cast<void*>(target),
                                      reinterpret_cast<void*>(replacement), original);
    if (!h.stub) {
        int error = shadowhook_get_errno();
        release_pins(h);
        return backend_error(r, error);
    }
    h.original = __atomic_load_n(original, __ATOMIC_ACQUIRE);
    h.info = {count + 1, target, replacement, reinterpret_cast<uint64_t>(h.original),
              slot, IJ2ART_INLINE_ACTIVE, 0};
    ++count;
    record(r, h);
}
} // namespace

bool ij2art_inline_permanent(void* target, void* replacement, void** original,
                              void** stub, ij2art_rsp& r) {
    if (*stub) return true;
    FaultSignals signals;
    if (!signals.ok) {
        message(r, IJ2ART_E_INLINE_STATE, "cannot enable fault protection signals");
        return false;
    }
    if (!initialize(r)) return false;
    *stub = shadowhook_hook_func_addr(target, replacement, original);
    if (*stub) return true;
    backend_error(r, shadowhook_get_errno());
    return false;
}

bool ij2art_inline_command(const ij2art_cmd& c, ij2art_rsp& r) {
    if (c.type < IJ2ART_CMD_INLINE_INIT || c.type > IJ2ART_CMD_INLINE_QUERY) return false;
    if (c.len != 0) { message(r, IJ2ART_E_INLINE_INVALID, "inline command takes no data bytes"); return true; }
    FaultSignals signals;
    if (!signals.ok) { message(r, IJ2ART_E_INLINE_STATE, "cannot enable fault protection signals"); return true; }
    switch (c.type) {
    case IJ2ART_CMD_INLINE_INIT:
        if (initialize(r)) {
            r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data),
                             "{\"backend\":\"shadowhook\",\"version\":\"%s\",\"mode\":\"unique\","
                             "\"address_only\":true,\"capacity\":%u}",
                             SHADOWHOOK_VERSION, IJ2ART_INLINE_SLOTS);
        }
        break;
    case IJ2ART_CMD_INLINE_ADD:
        add(c, r);
        break;
    case IJ2ART_CMD_INLINE_LIST:
        for (size_t i = 0; i < count; ++i) {
            memcpy(r.data + r.len, &hooks[i].info, sizeof(hooks[i].info));
            r.len += sizeof(hooks[i].info);
        }
        break;
    default: {
        if (!c.addr || c.addr > count) {
            message(r, IJ2ART_E_INLINE_NOT_FOUND, "inline hook id not found");
            break;
        }
        Hook& h = hooks[c.addr - 1];
        if (c.type == IJ2ART_CMD_INLINE_DEL && h.info.state != IJ2ART_INLINE_REMOVED) {
            if (h.info.state == IJ2ART_INLINE_ERROR) {
                message(r, IJ2ART_E_INLINE_STATE, "previous removal failed; restart the target process");
                break;
            }
            int error = shadowhook_unhook(h.stub);
            h.stub = nullptr; // Upstream consumes its task even when removal fails.
            h.info.backend_error = error;
            h.info.state = error ? IJ2ART_INLINE_ERROR : IJ2ART_INLINE_REMOVED;
            if (error) { backend_error(r, error); break; }
        }
        record(r, h);
        break;
    }
    }
    return true;
}

bool ij2art_inline_can_shutdown(ij2art_rsp& r) {
    for (size_t i = 0; i < count; ++i) {
        if (hooks[i].info.state != IJ2ART_INLINE_REMOVED) {
            message(r, IJ2ART_E_INLINE_STATE,
                    "native inline hooks remain; quiesce their callers and remove them before shutdown");
            return false;
        }
    }
    return true;
}

bool ij2art_inline_module_in_use(const void* base) {
    if (!base) return false;
    for (size_t i = 0; i < count; ++i) {
        if (hooks[i].info.state != IJ2ART_INLINE_ACTIVE) continue;
        const uint64_t addrs[2] = {hooks[i].info.target, hooks[i].info.replacement};
        for (uint64_t addr : addrs) {
            Dl_info info{};
            if (dladdr(reinterpret_cast<void*>(addr), &info) && info.dli_fbase == base)
                return true;
        }
    }
    return false;
}
