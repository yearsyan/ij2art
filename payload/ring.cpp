// Payload side of the control ring: the shared-memory command channel between the CLI and the
// payload. The ring is built and its worker started only after specialization has succeeded.
// The fd is kept open for the whole lifetime of the process, because it is the only anchor
// through which the CLI can find us from the outside. The worker waits on FUTEX_WAIT with a
// timeout, which is also how it reclaims uploads that have expired.
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include "../common/proto.h"
#include "ring.h"
#include "art.h"
#include "inline_hook.h"
#include "loader.h"

#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, "ij2art", __VA_ARGS__)

// The bionic headers do not bring in these two user-space macros, so we define them here; the
// values match the kernel uapi.
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

static uint8_t* g_map;                                // 64K shared region (MAP_SHARED)
static volatile struct ij2art_ring_hdr* g_hdr;
static struct ij2art_cmd* g_cmd;
static struct ij2art_rsp* g_rsp;
static int g_fd = -1;

// ---- futex (ordinary semantics: a shared mapping is keyed by inode plus page offset, so it
// naturally ends up with the same key as the CLI's mapping of the same file) ----
static long futex_wait(volatile uint32_t* u, uint32_t expect) {
    const timespec timeout{1, 0}; // Expire abandoned bounded DEX uploads even while idle.
    return syscall(SYS_futex, (uint32_t*)u, FUTEX_WAIT, expect, &timeout, NULL, 0);
}
static long futex_wake(volatile uint32_t* u) {
    return syscall(SYS_futex, (uint32_t*)u, FUTEX_WAKE, 1, NULL, NULL, 0);
}

static inline void seq_store(volatile uint32_t* u, uint32_t v) {
    __atomic_store_n((volatile uint32_t*)u, v, __ATOMIC_RELEASE);
}
static inline uint32_t seq_load(volatile uint32_t* u) {
    return __atomic_load_n((volatile uint32_t*)u, __ATOMIC_ACQUIRE);
}
static inline void flags_or(uint32_t bits) {
    __atomic_fetch_or((volatile uint32_t*)&g_hdr->flags, bits, __ATOMIC_RELAXED);
}

// ---- READ: process_vm_readv on ourselves, so a bad address returns EFAULT rather than
// raising SIGSEGV ----
static int do_read(uint64_t addr, uint64_t len, struct ij2art_rsp* r) {
    if (len == 0 || len > IJ2ART_RSP_DATA_MAX) return IJ2ART_E_2BIG;
    struct iovec local  = { r->data, len };
    struct iovec remote = { (void*)addr, len };
    ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    if (n != (ssize_t)len) return IJ2ART_E_FAULT;
    r->len = len;
    return 0;
}

// ---- WRITE: look the page up in /proc/self/maps and remember its original prot, add
// PROT_WRITE temporarily to read-only pages, then restore the original prot when done ----
// MTE caveat: a tagged address must be untagged before it is looked up in /proc/self/maps,
// because the addresses listed there carry no tag. memcpy, however, preserves the original
// tag -- under sync MTE, dereferencing a tagged pointer into the malloc heap requires the
// correct tag.
#define TAG_MASK 0x00ffffffffffffffULL
static int page_prot(uint64_t addr, int* prot) {
    uint64_t ua = addr & TAG_MASK;
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char line[512];
    int found = -1;
    while (fgets(line, sizeof(line), f)) {
        uint64_t s, e;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &s, &e, perms) != 3) continue;
        if (ua >= s && ua < e) {
            *prot = ((strchr(perms, 'r')) ? PROT_READ : 0)
                  | ((strchr(perms, 'w')) ? PROT_WRITE : 0)
                  | ((strchr(perms, 'x')) ? PROT_EXEC : 0);
            found = 0;
            break;
        }
    }
    fclose(f);
    return found;
}

static int do_write(uint64_t addr, const uint8_t* src, uint64_t len) {
    if (len == 0 || len > IJ2ART_CMD_DATA_MAX) return IJ2ART_E_2BIG;
    for (uint64_t off = 0; off < len; ) {
        uint64_t page = (addr + off) & ~4095ULL;
        uint64_t n = 4096 - ((addr + off) - page);
        if (n > len - off) n = len - off;
        int prot;
        if (page_prot(page, &prot) != 0) return IJ2ART_E_FAULT;
        if (prot & PROT_WRITE) {
            memcpy((void*)(addr + off), src + off, n);
        } else {
            // The mprotect is page-granular and lands on exactly one VMA page; restoring the
            // protection also puts the original R/X bits back
            if (mprotect((void*)page, 4096, prot | PROT_WRITE) != 0) return IJ2ART_E_FAULT;
            memcpy((void*)(addr + off), src + off, n);
            mprotect((void*)page, 4096, prot);
        }
        off += n;
    }
    return 0;
}

// ---- CALL: on arm64 the first 8 fixed arguments all live in x0..x7, so it is enough to cast
// the function pointer to the matching arity and call it ----
static uint64_t do_call(uint64_t fn, uint32_t n, const uint64_t* a) {
    switch (n) {
    case 0: return ((uint64_t(*)())fn)();
    case 1: return ((uint64_t(*)(uint64_t))fn)(a[0]);
    case 2: return ((uint64_t(*)(uint64_t, uint64_t))fn)(a[0], a[1]);
    case 3: return ((uint64_t(*)(uint64_t, uint64_t, uint64_t))fn)(a[0], a[1], a[2]);
    case 4: return ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t))fn)(a[0], a[1], a[2], a[3]);
    case 5: return ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(a[0], a[1], a[2], a[3], a[4]);
    case 6: return ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 7: return ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
    default: return ((uint64_t(*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    }
}

// ---- MODS: a full snapshot of the linker's modules, including the carrier/payload that are
// still loaded ----
struct mods_ctx { struct ij2art_rsp* r; uint32_t n; };

static int mods_cb(struct dl_phdr_info* i, size_t, void* d) {
    struct mods_ctx* c = (struct mods_ctx*)d;
    if (c->n >= IJ2ART_RSP_DATA_MAX / (uint32_t)sizeof(struct ij2art_modent)) {
        c->r->flags |= 1;  // truncation flag (the CLI shows a hint based on it)
        return 1;
    }
    struct ij2art_modent* e = (struct ij2art_modent*)
        (c->r->data + (size_t)c->n * sizeof(struct ij2art_modent));
    e->base = i->dlpi_addr;
    snprintf(e->name, sizeof(e->name), "%s",
             (i->dlpi_name && *i->dlpi_name) ? i->dlpi_name : "(exe)");
    c->n++;
    return 0;
}

// Returns true when SHUTDOWN was received; the caller replies first and then tears itself down.
static bool handle_cmd(const struct ij2art_cmd* c, struct ij2art_rsp* r) {
    memset(r, 0, sizeof(*r));
    r->type = c->type;
    r->id = c->id;
    r->session = c->session;
    switch (c->type) {
    case IJ2ART_CMD_PING: {
        int n = snprintf((char*)r->data, 128, "ij2art-payload pid=%d uid=%d",
                         getpid(), getuid());
        r->len = n > 0 ? (uint64_t)n : 0;
        break;
    }
    case IJ2ART_CMD_READ:
        r->status = do_read(c->addr, c->len, r);
        break;
    case IJ2ART_CMD_WRITE:
        r->status = do_write(c->addr, c->data, c->len);
        break;
    case IJ2ART_CMD_CALL:
        if (c->args_n > 8) r->status = IJ2ART_E_BADCMD;
        else r->retval = do_call(c->addr, c->args_n, c->args);
        break;
    case IJ2ART_CMD_MODS: {
        struct mods_ctx ctx = { r, 0 };
        dl_iterate_phdr(mods_cb, &ctx);
        r->len = (uint64_t)ctx.n * sizeof(struct ij2art_modent);
        break;
    }
    case IJ2ART_CMD_SHUTDOWN:
        if (!ij2art_inline_can_shutdown(*r)) break;
        if (!ij2art_art_shutdown(*r)) break;
        flags_or(IJ2ART_RMF_SHUTDOWN);  // set the flag before replying; the CLI sees it too
        return true;
    default:
        if (!ij2art_inline_command(*c, *r) && !ij2art_probe_command(*c, *r) && !ij2art_art_command(*c, *r) &&
            !ij2art_loader_command(*c, *r))
            r->status = IJ2ART_E_BADCMD;
    }
    return false;
}

// The control worker masquerades as one of the process's binder threads. The name lives in
// one place because two callers must agree byte for byte: worker() installs it as this
// thread's comm, and art.cpp's attach passes it as the JNI attach name. ART's CreatePeer
// renames the TID from JavaVMAttachArgs.name, so a divergent attach name would overwrite
// the comm-level disguise. 16 bytes matches the kernel's TASK_COMM_LEN.
const char* ij2art_ring_worker_name() {
    static char name[16];
    if (!name[0]) snprintf(name, sizeof(name), "Binder:%d_3", getpid());
    return name;
}

static void* worker(void*) {
    // Standard practice for a helper thread: block every blockable signal so that we do not
    // take over the job of ART's Signal Catcher.
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, nullptr);
    // The name blends into the binder thread list. This is a disguise at the comm level only;
    // a binder state audit can still tell, as noted in the README.
    pthread_setname_np(pthread_self(), ij2art_ring_worker_name());

    uint32_t last = seq_load(&g_hdr->rsp_seq);
    flags_or(IJ2ART_RMF_WORKER);
    // READY is published only after the consumer has been initialized, so the first command
    // cannot be mistaken for the initial sequence number.
    __atomic_store_n((uint64_t*)&g_hdr->magic, IJ2ART_RING_MAGIC, __ATOMIC_RELEASE);
    for (;;) {
        ij2art_art_tick();
        ij2art_loader_tick();
        uint32_t cur = seq_load(&g_hdr->cmd_seq);
        if (cur == last) {
            futex_wait(&g_hdr->cmd_seq, last);
            continue;
        }
        // While a single slot is in flight the client must not overwrite it; once the copy is
        // done, execution depends only on our own snapshot.
        struct ij2art_cmd command;
        memcpy(&command, g_cmd, sizeof(command));
        bool shutdown = handle_cmd(&command, g_rsp);
        last = cur;
        seq_store(&g_hdr->rsp_seq, cur);
        futex_wake(&g_hdr->rsp_seq);
        if (shutdown) {
            munmap(g_map, IJ2ART_RING_FDSIZE);
            close(g_fd);
            g_fd = -1;
            g_map = nullptr;
            return nullptr;
        }
    }
}

bool ij2art_ring_start() {
    int fd = memfd_create("jit-cache", 0);  // same name as ART's JIT cache; CLI uses size+magic
    if (fd < 0) { ALOGI("ring: memfd_create errno=%d", errno); return false; }
    if (ftruncate(fd, IJ2ART_RING_FDSIZE) != 0) {
        ALOGI("ring: ftruncate errno=%d", errno);
        close(fd);
        return false;
    }
    void* m = mmap(nullptr, IJ2ART_RING_FDSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { ALOGI("ring: mmap errno=%d", errno); close(fd); return false; }

    g_map = (uint8_t*)m;
    g_fd = fd;
    g_hdr = (volatile struct ij2art_ring_hdr*)(g_map + IJ2ART_RING_HDR_OFF);
    g_cmd = (struct ij2art_cmd*)(g_map + IJ2ART_RING_CMD_OFF);
    g_rsp = (struct ij2art_rsp*)(g_map + IJ2ART_RING_RSP_OFF);

    // Initialize the header: the fields are written first and magic last, so a reader that
    // observes a valid magic knows the protocol is ready
    struct ij2art_ring_hdr h;
    memset(&h, 0, sizeof(h));
    h.version = IJ2ART_PROTO_VER;
    h.hdr_len = sizeof(h);
    h.pid = getpid();
    memcpy((void*)g_hdr, &h, sizeof(h));
    // magic is published by the worker once it can consume commands.

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 1024 * 1024); // JNI method lookup needs more than the RPC-only stack.
    pthread_t t;
    int rc = pthread_create(&t, &attr, worker, nullptr);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        ALOGI("ring: pthread_create error=%d", rc);
        munmap(g_map, IJ2ART_RING_FDSIZE);
        close(g_fd);
        g_map = nullptr;
        g_fd = -1;
        return false;
    }
    return true;
}
