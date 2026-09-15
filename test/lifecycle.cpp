// Isolated-process regression test: it loads only the artifacts from this build and does not
// inject into the zygote or any other process.
#include <dlfcn.h>
#include <link.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>
#include "../common/proto.h"
#include "../common/state.h"

static_assert(offsetof(ij2art_cmd, session) == 8);
static_assert(offsetof(ij2art_cmd, args_n) == 16);
static_assert(offsetof(ij2art_cmd, addr) == 24);
static_assert(offsetof(ij2art_cmd, len) == 32);
static_assert(offsetof(ij2art_cmd, args) == 40);
static_assert(offsetof(ij2art_cmd, data) == 104);
static_assert(offsetof(ij2art_rsp, session) == 32);
static_assert(offsetof(ij2art_rsp, data) == 40);

static void require(bool ok, const char* msg) {
    if (!ok) { fprintf(stderr, "FAIL: %s\n", msg); exit(1); }
}
static uint64_t ms() {
    timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
struct Module { uintptr_t base; bool found; };
static int inspect(dl_phdr_info* info, size_t, void* data) {
    auto* m = (Module*)data;
    // Read the program headers for real, rather than relying only on a name that may already
    // have been erased.
    volatile unsigned type = 0;
    for (int n = 0; n < info->dlpi_phnum; ++n) type = info->dlpi_phdr[n].p_type;
    (void)type;
    if (info->dlpi_addr == m->base) m->found = true;
    return 0;
}
static bool listed(uintptr_t base) { Module m{base, false}; dl_iterate_phdr(inspect, &m); return m.found; }
static int threads() {
    DIR* d = opendir("/proc/self/task"); require(d != nullptr, "task list");
    int n = 0;
    while (auto* e = readdir(d)) if (e->d_name[0] != '.') ++n;
    closedir(d); return n;
}
static int ring_fd() {
    DIR* d = opendir("/proc/self/fd"); require(d != nullptr, "fd list");
    int found = -1;
    while (auto* e = readdir(d)) {
        char* end; long fd = strtol(e->d_name, &end, 10);
        if (*end || fd == dirfd(d)) continue;
        struct stat st;
        ij2art_ring_hdr h{};
        if (fstat((int)fd, &st) == 0 && st.st_size == IJ2ART_RING_FDSIZE &&
            pread((int)fd, &h, sizeof(h), 0) == sizeof(h) && h.magic == IJ2ART_RING_MAGIC &&
            h.version == IJ2ART_PROTO_VER) { found = dup((int)fd); break; }
    }
    closedir(d); return found;
}
static uint64_t echo(uint64_t value) { return value ^ 0xaabbccddULL; }
static void request(ij2art_ring_hdr* h, ij2art_cmd* c, ij2art_rsp* r,
                    uint32_t type, uint64_t session) {
    uint32_t seq = __atomic_load_n(&h->cmd_seq, __ATOMIC_ACQUIRE) + 1;
    require(__atomic_load_n(&h->rsp_seq, __ATOMIC_ACQUIRE) == seq - 1, "single in-flight");
    memset(c, 0, sizeof(*c));
    c->type = type; c->id = seq; c->session = session;
    if (type == IJ2ART_CMD_CALL) { c->addr = (uintptr_t)&echo; c->args_n = 1; c->args[0] = 123; }
    __atomic_store_n(&h->cmd_seq, seq, __ATOMIC_RELEASE);
    // Wake the other side through a shared futex on the same file mapping.
    syscall(98 /* __NR_futex AArch64 */, &h->cmd_seq, 1, 1, nullptr, nullptr, 0);
    uint64_t deadline = ms() + 3000;
    while (__atomic_load_n(&h->rsp_seq, __ATOMIC_ACQUIRE) != seq && ms() < deadline) usleep(1000);
    require(__atomic_load_n(&h->rsp_seq, __ATOMIC_ACQUIRE) == seq, "response timeout");
    require(r->type == type && r->id == seq && r->session == session && r->status == 0, "response identity/status");
    if (type == IJ2ART_CMD_PING) require(r->len > 0 && r->len <= IJ2ART_RSP_DATA_MAX, "ping data");
    if (type == IJ2ART_CMD_CALL) require(r->retval == echo(123), "CALL result");
}
int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "--park")) {
        puts("READY"); fflush(stdout);
        for (;;) pause();
    }
    require(argc == 3, "usage: lifecycle <carrier.so> <payload.so>");
    for (int i = 0; i < 20; ++i) {
        void* carrier = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL); require(carrier != nullptr, dlerror());
        auto* st = (ij2art_state*)dlsym(carrier, "g_state"); require(st != nullptr, "state export");
        require(st->version == IJ2ART_VERSION && st->magic == 0 && st->hook_installed == 0 && st->scratch_addr == 0,
                "constructor must not publish hooks or transfer scratch ownership");
        Dl_info info{}; require(dladdr(st, &info) != 0, "carrier dladdr");
        auto base = (uintptr_t)info.dli_fbase;
        require(listed(base), "carrier must remain linker-registered");
        require(dlclose(carrier) == 0, "carrier dlclose");
        require(!listed(base), "carrier must be unregistered by dlclose");
    }
    puts("PASS: 20 carrier load/enumerate/dlclose cycles");
    void* payload = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL); require(payload != nullptr, dlerror());
    auto start = (void(*)())dlsym(payload, "ij2art_after_specialize"); require(start != nullptr, "payload export");
    int before = threads();
    start();
    int fd = -1;
    for (int n = 0; n < 3000 && fd < 0; ++n) { fd = ring_fd(); if (fd < 0) usleep(1000); }
    require(fd >= 0, "worker READY");
    void* map = mmap(nullptr, IJ2ART_RING_FDSIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    require(map != MAP_FAILED, "ring map");
    auto* h = (ij2art_ring_hdr*)map;
    auto* c = (ij2art_cmd*)((char*)map + IJ2ART_RING_CMD_OFF);
    auto* r = (ij2art_rsp*)((char*)map + IJ2ART_RING_RSP_OFF);
    request(h, c, r, IJ2ART_CMD_PING, 0x123456789abcdef0ULL);
    request(h, c, r, IJ2ART_CMD_CALL, 0xfedcba9876543210ULL);
    request(h, c, r, IJ2ART_CMD_MODS, 99);
    request(h, c, r, IJ2ART_CMD_SHUTDOWN, 100);
    for (int n = 0; n < 3000 && threads() > before; ++n) usleep(1000);
    require(threads() == before, "worker exited");
    munmap(map, IJ2ART_RING_FDSIZE); close(fd);
    require(dlclose(payload) == 0, "payload dlclose after worker exit");
    puts("PASS: real payload READY/PING/CALL/MODS/SHUTDOWN, 64-bit sessions and worker exit");
}
