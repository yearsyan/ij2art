#include "inline_hook.h"
#include "loader.h"
#include "probe_buffer.h"
#include "../third_party/shadowhook/include/shadowhook.h"
#include <dlfcn.h>
#include <link.h>
#include <new>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

namespace {
struct Hook {
    ij2art_inline_info info{};
    void* stub = nullptr;
    void* original = nullptr;
    void* pins[3]{};
};
Hook hooks[IJ2ART_INLINE_SLOTS];
size_t count;

struct Probe {
    ij2art_probe_info info{}; // only immutable configuration is read by callbacks
    ij2art::ProbeBuffer* buffer = nullptr;
    void* stub = nullptr;
    void* pin = nullptr;
};
Probe probes[IJ2ART_PROBE_SLOTS];
size_t probe_count;

bool probe_at(uint64_t target) {
    for (size_t i = 0; i < probe_count; ++i)
        if (probes[i].info.target == target && probes[i].info.state != IJ2ART_PROBE_REMOVED)
            return true;
    return false;
}

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
    if (probe_at(target))
        return message(r, IJ2ART_E_INLINE_STATE, "an instruction probe already uses this target");
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

// Bypass libc so probing gettid/clock_gettime/syscall cannot recursively invoke
// those same observation points. No allocation, logging, unwinding or errno writes.
static __always_inline long probe_syscall(long nr, long arg0 = 0, long arg1 = 0) {
    register long x8 asm("x8") = nr;
    register long x0 asm("x0") = arg0;
    register long x1 asm("x1") = arg1;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory", "cc");
    return x0;
}

void observe_instruction(shadowhook_cpu_context_t* ctx, void* data) {
    auto& p = *static_cast<Probe*>(data);
    if (!p.buffer->enabled()) return;
    const auto& config = p.info;
    const uint32_t tid = static_cast<uint32_t>(probe_syscall(SYS_gettid));
    if (config.tid && tid != config.tid) return;
    if (config.condition_reg != IJ2ART_PROBE_NO_CONDITION &&
        ctx->regs[config.condition_reg] != config.condition_value) return;
    p.buffer->capture([&](ij2art_probe_event& event) {
        timespec ts{};
        const bool clock_ok = probe_syscall(SYS_clock_gettime, CLOCK_MONOTONIC,
                                           reinterpret_cast<long>(&ts)) == 0;
        event.ts_ns = clock_ok ? static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec : 0;
        event.tid = tid;
        event.flags = clock_ok ? 0 : IJ2ART_PROBE_CLOCK_FAILED;
        event.pc = ctx->pc;
        event.sp = ctx->sp;
        event.nzcv = ctx->pstate & 0xf0000000ULL;
        for (size_t i = 0; i < 31; ++i) event.regs[i] = ctx->regs[i];
    });
}

ij2art_probe_info probe_info(const Probe& p) {
    auto info = p.info;
    p.buffer->stats(info);
    return info;
}
void probe_record(ij2art_rsp& r, const Probe& p) {
    const auto info = probe_info(p);
    memcpy(r.data, &info, sizeof(info));
    r.len = sizeof(info);
    r.retval = info.id;
}
void probe_error(ij2art_rsp& r, int code) {
    backend_error(r, code);
    r.status = IJ2ART_E_PROBE_BACKEND;
}
void add_probe(const ij2art_cmd& c, ij2art_rsp& r) {
    if ((c.addr & 3) || !mapped(c.addr, 4, true) || c.args[0] > INT32_MAX ||
        (c.args[2] > 30 && c.args[2] != IJ2ART_PROBE_NO_CONDITION))
        return message(r, IJ2ART_E_PROBE_INVALID,
                       "require a readable aligned executable instruction, a valid tid and x0..x30 condition");
    if (c.args[0]) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/task/%u", static_cast<unsigned>(c.args[0]));
        if (access(path, F_OK))
            return message(r, IJ2ART_E_PROBE_INVALID, "tid does not belong to this process");
    }
    Dl_info target{}, observer{};
    if (!dladdr(reinterpret_cast<void*>(c.addr), &target) ||
        !dladdr(reinterpret_cast<void*>(&observe_instruction), &observer) ||
        target.dli_fbase == observer.dli_fbase)
        return message(r, IJ2ART_E_PROBE_INVALID, "probe must target a loaded ELF outside the payload");
    if (probe_at(c.addr))
        return message(r, IJ2ART_E_PROBE_STATE, "instruction already registered; use probe list/query");
    for (size_t i = 0; i < count; ++i)
        if (hooks[i].info.target == c.addr && hooks[i].info.state != IJ2ART_INLINE_REMOVED)
            return message(r, IJ2ART_E_PROBE_STATE, "an inline hook already uses this target");
    if (probe_count == IJ2ART_PROBE_SLOTS)
        return message(r, IJ2ART_E_PROBE_LIMIT, "instruction probe record limit reached");
    Probe& p = probes[probe_count];
    if (!pin(c.addr, p.pin, true))
        return message(r, IJ2ART_E_PROBE_INVALID, "cannot retain the instruction's ELF");
    uint32_t instruction = 0;
    iovec local{&instruction, sizeof(instruction)}, remote{reinterpret_cast<void*>(c.addr), sizeof(instruction)};
    bool readable = process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == sizeof(instruction);
    if (!readable || !initialize(r)) {
        if (p.pin) dlclose(p.pin);
        p.pin = nullptr;
        if (!readable) message(r, IJ2ART_E_PROBE_INVALID, "cannot read the original instruction");
        else r.status = IJ2ART_E_PROBE_BACKEND;
        return;
    }
    p.buffer = new (std::nothrow) ij2art::ProbeBuffer;
    if (!p.buffer) {
        if (p.pin) dlclose(p.pin);
        p.pin = nullptr;
        return message(r, IJ2ART_E_PROBE_LIMIT, "cannot allocate probe buffer");
    }
    p.info = {probe_count + 1, c.addr, c.args[1], 0, 0, 0, 0, c.args[3],
              static_cast<uint32_t>(c.args[0]), static_cast<uint32_t>(c.args[2]),
              IJ2ART_PROBE_ACTIVE, 0, instruction, IJ2ART_PROBE_CAPACITY};
    p.buffer->start(c.args[1]); // callback state must be ready before publishing the patch
    // Arbitrary instructions can have live SIMD registers. Preserve them even
    // though only GPRs are reported: the compiler may use SIMD inside our callback.
    p.stub = shadowhook_intercept_instr_addr(reinterpret_cast<void*>(c.addr), observe_instruction,
                                            &p, SHADOWHOOK_INTERCEPT_WITH_FPSIMD_READ_WRITE);
    if (!p.stub) {
        const int error = shadowhook_get_errno();
        p.buffer->stop();
        // Upstream can install its launcher before allocating the interceptor.
        // A failed install therefore does not prove the instruction is restored.
        // Retain the ELF/buffer and reserve this address until process restart.
        p.info.state = IJ2ART_PROBE_ERROR;
        p.info.backend_error = error;
        ++probe_count;
        probe_error(r, error);
        r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data),
                         "probe id=%llu: ShadowHook error=%d: %s; inspect probe query and restart the target process",
                         static_cast<unsigned long long>(p.info.id), error, shadowhook_to_errmsg(error));
        return;
    }
    ++probe_count;
    probe_record(r, p);
}
} // namespace

bool ij2art_inline_permanent(void* target, void* replacement, void** original,
                              void** stub, ij2art_rsp& r) {
    if (*stub) return true;
    if (probe_at(reinterpret_cast<uint64_t>(target))) {
        message(r, IJ2ART_E_INLINE_STATE, "an instruction probe already uses this target");
        return false;
    }
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
    for (size_t i = 0; i < probe_count; ++i) {
        if (probes[i].info.state != IJ2ART_PROBE_REMOVED) {
            message(r, IJ2ART_E_PROBE_STATE,
                    "instruction probes remain; quiesce their callers and remove them before shutdown");
            return false;
        }
    }
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
    for (size_t i = 0; i < probe_count; ++i) {
        if (probes[i].info.state == IJ2ART_PROBE_REMOVED) continue;
        Dl_info info{};
        if (dladdr(reinterpret_cast<void*>(probes[i].info.target), &info) && info.dli_fbase == base)
            return true;
    }
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

bool ij2art_probe_command(const ij2art_cmd& c, ij2art_rsp& r) {
    if (c.type < IJ2ART_CMD_PROBE_ADD || c.type > IJ2ART_CMD_PROBE_READ) return false;
    if (c.len != 0) {
        message(r, IJ2ART_E_PROBE_INVALID, "probe commands take no data bytes");
        return true;
    }
    if (c.type == IJ2ART_CMD_PROBE_LIST) {
        for (size_t i = 0; i < probe_count; ++i) {
            const auto info = probe_info(probes[i]);
            memcpy(r.data + r.len, &info, sizeof(info));
            r.len += sizeof(info);
        }
        return true;
    }
    if (c.type == IJ2ART_CMD_PROBE_ADD) {
        FaultSignals signals;
        if (!signals.ok) message(r, IJ2ART_E_PROBE_STATE, "cannot enable fault protection signals");
        else add_probe(c, r);
        return true;
    }
    if (!c.addr || c.addr > probe_count) {
        message(r, IJ2ART_E_PROBE_NOT_FOUND, "instruction probe id not found");
        return true;
    }
    auto& p = probes[c.addr - 1];
    if (c.type == IJ2ART_CMD_PROBE_READ) {
        if (!c.args[1] || c.args[1] > IJ2ART_PROBE_READ_MAX) {
            message(r, IJ2ART_E_PROBE_INVALID, "probe read limit must be 1..48");
            return true;
        }
        ij2art_probe_batch batch{};
        batch.info = p.info;
        const int error = p.buffer->read(c.args[0], static_cast<uint32_t>(c.args[1]), batch,
                                          r.data + sizeof(batch));
        if (error) message(r, error, error == IJ2ART_E_PROBE_BUSY
                            ? "probe buffer busy; retry the same cursor" : "probe cursor is ahead of captured events");
        else {
            memcpy(r.data, &batch, sizeof(batch));
            r.len = sizeof(batch) + batch.count * sizeof(ij2art_probe_event);
        }
        return true;
    }
    if (c.type == IJ2ART_CMD_PROBE_DEL && p.info.state != IJ2ART_PROBE_REMOVED) {
        if (p.info.state == IJ2ART_PROBE_ERROR) {
            message(r, IJ2ART_E_PROBE_STATE, "probe backend failed; restart the target process");
            return true;
        }
        FaultSignals signals;
        if (!signals.ok) {
            message(r, IJ2ART_E_PROBE_STATE, "cannot enable fault protection signals");
            return true;
        }
        p.buffer->stop();
        const int error = shadowhook_unintercept(p.stub);
        p.stub = nullptr; // consumed by the backend even on removal failure
        p.info.backend_error = error;
        p.info.state = error ? IJ2ART_PROBE_ERROR : IJ2ART_PROBE_REMOVED;
        if (error) { probe_error(r, error); return true; }
        // Keep callback storage, events and file-backed ELF pins alive; no reuse.
    }
    probe_record(r, p);
    return true;
}
