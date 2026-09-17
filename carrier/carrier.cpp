// carrier: the library injected into zygote.
// Its job is to hook the specialization-path function in the GOT of **every loaded
// library** (the same function may be called from several libraries, so patching only one
// of them is the classic miss). When a target App is hit, the child process dlopens the
// embedded payload and the GOT is then restored. A non-target child process is torn down
// entirely with a dlclose through a dedicated trampoline page (teardown_stub.S), so that
// no mapping or soinfo registration is left behind in a non-target App.
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <errno.h>
#include <android/log.h>
#include <android/dlext.h>
#include "../common/state.h"

// ---------------- exported symbols: CLI locates them via dynsym offsets ----------------
extern "C" {

// The extern gives these symbols explicit external linkage (in C++ a const global defaults
// to internal linkage and would be discarded as dead code); used protects them from
// --gc-sections; and default visibility places them in dynsym so the CLI can find them.
__attribute__((visibility("default"), used))
extern const char ij2art_ident[] = "ij2art-carrier/4";  // increment on ABI change; the CLI
                                                        // version-matches this

__attribute__((visibility("default")))
extern struct ij2art_state g_state;

__attribute__((visibility("default")))
int ij2art_setup(int payload_fd, const char* targets_csv, uint32_t flags);


} // extern "C"

struct ij2art_state g_state;  // the only definition point; the extern "C" block holds declarations

// Diagnostic logging is silent by default so as not to leave forensic traces for the
// system; it starts emitting only after inject/targets --verbose sets IJ2ART_F_VERBOSE. At
// runtime it only reads memory and does not access the filesystem.
static bool verbose() { return (g_state.flags & IJ2ART_F_VERBOSE) != 0; }
#define ALOGI(...) do { if (verbose()) \
    __android_log_print(ANDROID_LOG_INFO, "ij2art", __VA_ARGS__); } while (0)

// ---------------- payload (embedded at build time) ----------------
extern "C" {
extern const char _binary_payload_so_start[];
extern const char _binary_payload_so_end[];
}

// memfd_create + write + dlopen on the spot in the child process. This leaves no inherited
// fd in zygote, because otherwise the FileDescriptorTable allowlist check performed when
// zygote forks would abort outright. Returns the payload handle (from which the
// post-domain-switch start entry is looked up), or nullptr on failure.
static void* load_payload() {
    size_t size = (size_t)(_binary_payload_so_end - _binary_payload_so_start);
    if (size == 0) return nullptr;
    int fd = memfd_create("jit-cache", 0);  // name matches the App's own JIT cache
    if (fd < 0) { ALOGI("payload: memfd_create failed errno=%d", errno); return nullptr; }
    size_t off = 0;
    while (off < size) {
        ssize_t n = write(fd, _binary_payload_so_start + off, size - off);
        if (n <= 0) { close(fd); ALOGI("payload: write failed"); return nullptr; }
        off += (size_t)n;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    android_dlextinfo ext{};
    ext.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    ext.library_fd = fd;
    void* h = android_dlopen_ext(path, RTLD_NOW, &ext);
    if (!h) ALOGI("payload: dlopen failed: %s", dlerror());
    close(fd);
    return h;
}

// ---------------- GOT hook framework ----------------
static bool g_payload_done;  // dlopen only once per process (COW after fork isolates per process)

// Record the true permissions and the original value of each slot. The records are kept on
// failure, and unloading is allowed only once everything is clean.
static bool write_slot(uint64_t* slot, uint64_t value, int prot) {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) return false;
    uintptr_t page = (uintptr_t)slot & ~((uintptr_t)ps - 1);
    if (mprotect((void*)page, (size_t)ps, prot | PROT_WRITE) != 0) return false;
    __atomic_store_n(slot, value, __ATOMIC_RELEASE);
    return mprotect((void*)page, (size_t)ps, prot) == 0;
}

static int slot_prot(uint64_t* slot) {
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return -1;
    char line[512], perms[5];
    uintptr_t lo, hi;
    int prot = -1;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) == 3 &&
            (uintptr_t)slot >= lo && (uintptr_t)slot + 8 <= hi) {
            prot = (perms[0] == 'r' ? PROT_READ : 0) |
                   (perms[1] == 'w' ? PROT_WRITE : 0) |
                   (perms[2] == 'x' ? PROT_EXEC : 0);
            break;
        }
    }
    fclose(f);
    return prot;
}

#define MAX_SLOTS 24
struct saved_slot { uint64_t* addr; uint64_t value; int prot; };
struct hook_set {
    const char* sym;
    uint64_t hook;
    uint64_t orig;
    saved_slot slots[MAX_SLOTS];
    int nslots;
};
static bool g_patch_failed;

static bool restore_set(hook_set* s) {
    bool ok = true;
    for (int i = 0; i < s->nslots; ++i) {
        auto& slot = s->slots[i];
        if (!slot.addr) continue;
        if (write_slot(slot.addr, slot.value, slot.prot)) slot.addr = nullptr;
        else ok = false;
    }
    if (ok) s->nslots = 0;
    return ok;
}

// ---------------- hook implementations ----------------
// prototype: int selinux_android_setcontext(uid_t, bool isSystemServer, const char* seinfo, const char* pkgname)
//   -- the ordinary forkAndSpecialize path (the arguments carry the uid and package name)
typedef int (*setcontext_fn)(uid_t, bool, const char*, const char*);
typedef int (*setcon_fn)(const char*);
typedef int (*setresX_fn)(uid_t, uid_t, uid_t);

static hook_set g_hs_setcontext, g_hs_setcon, g_hs_setresuid, g_hs_setresgid;

static void dump_con(const char* stage, long a) {
    char ctx[128] = {0};
    int f = open("/proc/self/attr/current", O_RDONLY);
    if (f >= 0) { read(f, ctx, sizeof(ctx) - 1); close(f); }
    char* nl = strchr(ctx, '\n'); if (nl) *nl = 0;
    ALOGI("spec[%s]: arg=%ld uid=%d pid=%d con=%s", stage, a, (int)getuid(), (int)getpid(), ctx);
}

// Erase the trace of an environment variable: zero out the content of the string on the
// heap and remove it from environ. (New entries added by setenv do not go into the initial
// stack region that /proc/self/environ reads, but they are visible to getenv and to environ
// traversal inside the process.)
static void scrub_env(const char* key) {
    extern char** environ;
    size_t klen = strlen(key);
    if (environ) {
        for (char** e = environ; *e; e++) {
            if (!strncmp(*e, key, klen) && (*e)[klen] == '=') {
                memset(*e + klen + 1, 0, strlen(*e + klen + 1));
            }
        }
    }
    unsetenv(key);
}

// In a target App the carrier keeps its linker registration and mappings; in a non-target
// child process it is deregistered fully with a dlclose through a dedicated trampoline page
// (see teardown_stub.S), so it does not remain in the process as a "dead mapping plus a dead
// soinfo". The trampoline bytes are linked into .rodata and copied to an RX page at runtime.
extern "C" {
extern const unsigned char __ij2art_teardown_start[];
extern const unsigned char __ij2art_teardown_end[];
extern void __ij2art_hook_shim();  // the real GOT target (teardown_stub.S): it pushes a
                                   // context block, then tail-jumps to the C implementation
// The shim writes it before any code touches the registers; the specialization path is
// single-threaded, so there is no race.
uint64_t g_entry_save;               // base of the context block (x19-x28/fp/lr), from which
                                     // the trampoline rebuilds the context
int hook_setcontext_impl(uid_t uid, bool is_system_server,
                         const char* seinfo, const char* pkgname);
}

struct TeardownDesc {
    uintptr_t orig, dlclose, handle, save;
    uintptr_t a0, a1, a2, a3;
};
static uintptr_t g_dlclose_fn;  // dlsym cached on first teardown (COW-inherited after fork)

// For the non-target path only: copy the stub into one page, flip it RW->RX, and bl into it
// to call __loader_dlclose(self_handle); then rebuild the registers and stack from the
// context block pushed by the shim and tail-jump to the original setcontext. The stub never
// returns: the carrier is in the process of being unmapped, and there is no frame to return
// to. If any step fails this returns false, and the caller falls back to the old behaviour of
// keeping the carrier and calling the original function directly.
static bool teardown_via_trampoline(uid_t a0, bool a1, const char* a2, const char* a3) {
    if (g_state.magic != IJ2ART_MAGIC || !g_state.self_handle || !g_hs_setcontext.orig)
        return false;
    // The context block must lie on this thread's stack and above the current frame;
    // otherwise it is treated as abnormal and the safe path is taken.
    uint64_t probe;
    uint64_t here = (uint64_t)&probe;
    if (g_entry_save < here || g_entry_save - here > (1u << 20)) return false;
    if (!g_dlclose_fn) {
        g_dlclose_fn = (uintptr_t)dlsym(RTLD_DEFAULT, "__loader_dlclose");
        if (!g_dlclose_fn) g_dlclose_fn = (uintptr_t)dlsym(RTLD_DEFAULT, "dlclose");
        if (!g_dlclose_fn) return false;
    }
    long ps = sysconf(_SC_PAGESIZE);
    size_t code = (size_t)(__ij2art_teardown_end - __ij2art_teardown_start);
    if (ps < 4096 || !code || sizeof(TeardownDesc) > (size_t)ps / 4 ||
        code > (size_t)ps / 2)
        return false;
    void* page = mmap(nullptr, (size_t)ps, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return false;
    memcpy(page, __ij2art_teardown_start, code);
    auto* desc = (TeardownDesc*)((char*)page + ps / 2);
    desc->orig = g_hs_setcontext.orig;
    desc->dlclose = g_dlclose_fn;
    desc->handle = g_state.self_handle;
    desc->save = g_entry_save;
    desc->a0 = (uintptr_t)a0;
    desc->a1 = (uintptr_t)a1;
    desc->a2 = (uintptr_t)a2;
    desc->a3 = (uintptr_t)a3;
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        munmap(page, (size_t)ps);
        return false;
    }
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t, void*))page)(
        (uint64_t)a0, (uint64_t)a1, (uintptr_t)a2, (uintptr_t)a3, desc);
    return true;  // unreachable: stub never returns
}

int hook_setcontext_impl(uid_t uid, bool is_system_server,
                         const char* seinfo, const char* pkgname) {
    restore_set(&g_hs_setcontext);
    restore_set(&g_hs_setcon);
    restore_set(&g_hs_setresuid);
    restore_set(&g_hs_setresgid);

    bool want = false;
    if (g_state.magic == IJ2ART_MAGIC && !g_payload_done && !is_system_server) {
        uint32_t appid = uid % 100000u;
        want = (g_state.flags & IJ2ART_F_ALL_USER_APPS) && appid >= 10000u && appid < 20000u;
        for (uint32_t i = 0; !want && pkgname && i < g_state.targets_count &&
             i < IJ2ART_MAX_TARGETS; ++i) {
            want = !strcmp(pkgname, g_state.targets[i]);
        }
    }
    if (want) {
        // The constructor does not start the worker; it is started only once setcontext has
        // returned successfully.
        setenv("ij2art_pkg", pkgname ? pkgname : "", 1);
        void* handle = load_payload();
        scrub_env("ij2art_pkg");
        g_payload_done = true;
        typedef void (*start_fn)();
        start_fn start =
            handle ? (start_fn)dlsym(handle, "ij2art_after_specialize") : nullptr;
        int rc = ((setcontext_fn)g_hs_setcontext.orig)(uid, is_system_server, seinfo, pkgname);
        if (rc == 0 && start) start();
        return rc;
    }
    // Non-target App: full teardown (the GOT was already restored above); once it succeeds,
    // control never returns to carrier code. system_server is never torn down -- the same
    // mechanism would work, but a crash there costs a soft brick, so keeping the mapping is
    // preferred. The original ra/sp have been captured by the shim (teardown_stub.S).
    if (!is_system_server &&
        teardown_via_trampoline(uid, is_system_server, seinfo, pkgname))
        __builtin_unreachable();
    return ((setcontext_fn)g_hs_setcontext.orig)(uid, is_system_server, seinfo, pkgname);
}

static int hook_setcon(const char* con) {
    restore_set(&g_hs_setcon);
    ALOGI("setcon hit: con=%s uid=%d pid=%d magic=%d", con ? con : "(null)",
          (int)getuid(), (int)getpid(), g_state.magic == IJ2ART_MAGIC ? 1 : 0);
    return ((setcon_fn)g_hs_setcon.orig)(con);
}

static int hook_setresuid(uid_t r, uid_t e, uid_t s) {
    restore_set(&g_hs_setresuid);
    dump_con("setresuid", r);
    return ((setresX_fn)g_hs_setresuid.orig)(r, e, s);
}

static int hook_setresgid(gid_t r, gid_t e, gid_t s) {
    restore_set(&g_hs_setresgid);
    dump_con("setresgid", r);
    return ((setresX_fn)g_hs_setresgid.orig)((uid_t)r, (uid_t)e, (uid_t)s);
}

// ---------------- all-lib GOT scan ----------------
struct dyn_ctx {
    uintptr_t base;
    const Elf64_Sym* symtab;
    const char* strtab;
    const Elf64_Rela* jmprel; size_t jmprel_n;
    const Elf64_Rela* rela;   size_t rela_n;
};

static hook_set* g_all_sets[4];

static void patch_relas(const Elf64_Rela* rela, size_t n, uintptr_t base,
                        const Elf64_Sym* symtab, const char* strtab) {
    for (size_t i = 0; i < n; i++) {
        uint32_t idx = ELF64_R_SYM(rela[i].r_info);
        const char* name = strtab + symtab[idx].st_name;
        for (auto* s : g_all_sets) {
            if (strcmp(name, s->sym)) continue;
            if (s->nslots >= MAX_SLOTS) { g_patch_failed = true; continue; }
            uint64_t* slot = (uint64_t*)(base + rela[i].r_offset);
            bool seen = false;
            for (int j = 0; j < s->nslots; ++j) seen |= s->slots[j].addr == slot;
            if (seen) continue;
            int prot = slot_prot(slot);
            if (prot < 0) { g_patch_failed = true; continue; }
            if (!s->orig) s->orig = *slot;
            s->slots[s->nslots++] = { slot, *slot, prot };
            if (!write_slot(slot, s->hook, prot)) g_patch_failed = true;
        }
    }
}

static int phdr_cb(struct dl_phdr_info* info, size_t, void*) {
    // Skip ourselves (loaded from a memfd, so dlpi_name is something like /proc/self/fd/N).
    if (!info->dlpi_name || !strstr(info->dlpi_name, ".so")) return 0;

    dyn_ctx c = {};
    c.base = (uintptr_t)info->dlpi_addr;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_DYNAMIC) continue;
        const Elf64_Dyn* d = (const Elf64_Dyn*)(c.base + ph->p_vaddr);
        for (; d->d_tag != DT_NULL; d++) {
            switch (d->d_tag) {
                case DT_SYMTAB:   c.symtab  = (const Elf64_Sym*)(c.base + d->d_un.d_ptr); break;
                case DT_STRTAB:   c.strtab  = (const char*)(c.base + d->d_un.d_ptr);      break;
                case DT_JMPREL:   c.jmprel  = (const Elf64_Rela*)(c.base + d->d_un.d_ptr); break;
                case DT_PLTRELSZ: c.jmprel_n = d->d_un.d_val / sizeof(Elf64_Rela);        break;
                case DT_RELA:     c.rela    = (const Elf64_Rela*)(c.base + d->d_un.d_ptr); break;
                case DT_RELASZ:   c.rela_n  = d->d_un.d_val / sizeof(Elf64_Rela);         break;
            }
        }
    }
    if (c.symtab && c.strtab) {
        patch_relas(c.jmprel, c.jmprel_n, c.base, c.symtab, c.strtab);
        patch_relas(c.rela,   c.rela_n,   c.base, c.symtab, c.strtab);
    }
    return 0;
}

// The constructor runs once, in zygote only (children created by fork inherit the result
// and do not run it again).
__attribute__((constructor)) static void carrier_ctor() {
    g_state.version = IJ2ART_VERSION;
    g_state.payload_fd = -1;

    g_hs_setcontext = { "selinux_android_setcontext", (uint64_t)&__ij2art_hook_shim, 0, {}, 0 };
    g_hs_setcon     = { "selinux_android_setcon",     (uint64_t)&hook_setcon,     0, {}, 0 };
    g_hs_setresuid  = { "setresuid",                  (uint64_t)&hook_setresuid,  0, {}, 0 };
    g_hs_setresgid  = { "setresgid",                  (uint64_t)&hook_setresgid,  0, {}, 0 };
    g_all_sets[0] = &g_hs_setcontext; g_all_sets[1] = &g_hs_setcon;
    g_all_sets[2] = &g_hs_setresuid;  g_all_sets[3] = &g_hs_setresgid;

    // Keep r_map, solist and dynstr so that a later dlclose can deregister us normally.
    // Nothing is hooked here yet: setup is called only after the CLI has finished
    // registering resources.
}

// ---------------- CLI remote-call entry points ----------------
static void fill_targets(const char* csv) {
    g_state.targets_count = 0;
    if (!csv || !*csv) return;
    char buf[2048];
    strncpy(buf, csv, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    char* save = nullptr;
    for (char* t = strtok_r(buf, ",", &save);
         t && g_state.targets_count < IJ2ART_MAX_TARGETS;
         t = strtok_r(nullptr, ",", &save)) {
        strncpy(g_state.targets[g_state.targets_count], t, 127);
        g_state.targets[g_state.targets_count][127] = 0;
        g_state.targets_count++;
    }
}

extern "C" int ij2art_setup(int payload_fd, const char* targets_csv, uint32_t flags) {
    g_state.payload_fd = payload_fd;
    g_state.flags = flags;
    fill_targets(targets_csv);
    g_state.version = IJ2ART_VERSION;
    g_patch_failed = false;
    dl_iterate_phdr(phdr_cb, nullptr);
    g_state.hook_installed =
        (g_hs_setcontext.nslots ? IJ2ART_HOOK_OK : 0) |
        (g_hs_setcon.nslots ? IJ2ART_HOOK_SETCON : 0) |
        (g_hs_setresuid.nslots ? 8u : 0) |
        (g_hs_setresgid.nslots ? 16u : 0);
    if (g_patch_failed || !g_hs_setcontext.nslots) return -1;
    __atomic_store_n(&g_state.magic, IJ2ART_MAGIC, __ATOMIC_RELEASE);
    return 0;
}

// The CLI calls this after stopping the whole thread group; dlclose is allowed only if
// every slot was restored successfully.
extern "C" __attribute__((visibility("default")))
int ij2art_unhook() {
    bool ok = restore_set(&g_hs_setcontext);
    ok = restore_set(&g_hs_setcon) && ok;
    ok = restore_set(&g_hs_setresuid) && ok;
    ok = restore_set(&g_hs_setresgid) && ok;
    if (!ok) return -1;
    g_state.hook_installed = 0;
    __atomic_store_n(&g_state.magic, 0, __ATOMIC_RELEASE);
    return 0;
}
