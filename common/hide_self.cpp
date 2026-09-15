// See hide_self.h. Note that the code in this file runs inside each process's own dlopen
// flow.
#include "hide_self.h"
#include <dlfcn.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG_MASK_UPTR 0x00ffffffffffffffULL

static struct r_debug* find_r_debug() {
    // The linker fills DT_DEBUG only in the dynamic section of the **main executable**; in
    // a shared library it stays empty.
    struct r_debug* rd = nullptr;
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        for (int j = 0; j < info->dlpi_phnum; j++) {
            const Elf64_Phdr* ph = &info->dlpi_phdr[j];
            if (ph->p_type != PT_DYNAMIC) continue;
            const Elf64_Dyn* d = (const Elf64_Dyn*)(info->dlpi_addr + ph->p_vaddr);
            for (; d->d_tag != DT_NULL; d++) {
                if (d->d_tag == DT_DEBUG && d->d_un.d_ptr) {
                    *(struct r_debug**)data = (struct r_debug*)d->d_un.d_ptr;
                    return 1;
                }
            }
        }
        return 0;
    }, &rd);
    return rd;
}

// Wipe a single C string buffer in place by overwriting its contents with '0', keeping its
// length and leaving the structure that owns it intact.
static void zap_string(const char* s) {
    if (!s) return;
    size_t n = strlen(s);
    if (n && n < 4096) memset((void*)s, '0', n);
}

struct rw_range { uint64_t s, e; };

// Collect the writable ranges (anonymous heap + linker64). Every later scan and dereference
// validates its address against them first.
static int collect_rw_ranges(rw_range* out, int maxn) {
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    int n = 0;
    char line[512];
    while (n < maxn && fgets(line, sizeof(line), f)) {
        uint64_t s, e; char fl[8];
        if (sscanf(line, "%lx-%lx %4s", &s, &e, fl) != 3) continue;
        if (fl[0] != 'r' || fl[1] != 'w') continue;
        bool anon = strchr(line, '/') == nullptr;
        bool is_linker = strstr(line, "linker64") != nullptr;
        if (!anon && !is_linker) continue;
        out[n++] = { s, e };
    }
    fclose(f);
    return n;
}

static bool in_ranges(const rw_range* rs, int n, uint64_t p) {
    for (int i = 0; i < n; i++) if (p >= rs[i].s && p < rs[i].e) return true;
    return false;
}

// Find strings in every writable range whose contents are our name, and wipe them all (for
// example the key copies belonging to handles_map).
static int zap_string_copies(const rw_range* rs, int n, const char* path) {
    int zapped = 0;
    size_t plen = strlen(path);
    if (!plen) return 0;
    for (int i = 0; i < n; i++) {
        if (rs[i].e - rs[i].s > 64 * 1024 * 1024) continue;
        for (uint64_t a = rs[i].s; a + plen <= rs[i].e; a++) {
            if (*(const char*)a == path[0] && memcmp((const void*)a, path, plen) == 0) {
                memset((void*)a, '0', plen);
                zapped++;
            }
        }
    }
    return zapped;
}

ij2art_hide_result ij2art_hide_self() {
    ij2art_hide_result res = {};
    Dl_info di = {};
    if (!dladdr((void*)&ij2art_hide_self, &di) || !di.dli_fbase) {
        __android_log_print(ANDROID_LOG_INFO, "ij2art", "hide_self: dladdr failed");
        return res;
    }
    uintptr_t my_base = (uintptr_t)di.dli_fbase;

    struct r_debug* rd = find_r_debug();
    if (!rd) {
        __android_log_print(ANDROID_LOG_INFO, "ij2art", "hide_self: r_debug not found");
        return res;
    }
    res.rd = rd;

    link_map* lm = nullptr;
    for (link_map* l = rd->r_map; l; l = l->l_next) {
        if (l->l_addr == my_base) { lm = l; break; }
    }
    if (!lm) {
        __android_log_print(ANDROID_LOG_INFO, "ij2art",
            "hide_self: we are not present in r_map (base=%p r_map_head=%p)", (void*)my_base, (void*)rd->r_map);
        return res;
    }
    res.lm = lm;

    // Remember our two names: l_name (the path passed to dlopen, for example
    // /proc/self/fd/N) and the realpath (the memfd path). The latter is found by scanning
    // the pointer fields of the soinfo struct.
    char name_l[256] = {0};
    char name_real[256] = {0};
    const char* lname = (const char*)((uintptr_t)lm->l_name & TAG_MASK_UPTR);
    if (lname) strncpy(name_l, lname, sizeof(name_l) - 1);

    // 1) Unlink ourselves from the r_map/solist chain.
    link_map* prev = lm->l_prev;
    link_map* next = lm->l_next;
    if (prev) prev->l_next = next;
    if (next) next->l_prev = prev;
    if (rd->r_map == lm) rd->r_map = next;
    // critical: never null our own l_prev/l_next! Keep them pointing at the old neighbours
    // so that later, when the linker dlcloses us (notify_gdb_of_unload), a non-null l_prev
    // makes it take the normal node path, which is a no-op; if they were nulled, the linker
    // would mistake us for the head of the chain and null the head pointer of the entire
    // r_map (a real-device bug: once the head is lost, every later injected hide can no
    // longer find itself).
    (void)lm;

    // 2) Wipe the l_name buffer.
    if (lname) zap_string(lname);

    // collect the valid writable ranges; every later dereference is validated against them
    // first
    static rw_range rs[1024];
    int rn = collect_rw_ranges(rs, 1024);

    // 3) scan the window around the soinfo struct for pointer fields that point at our
    //    path strings (realpath_, soname_ and so on), and wipe the target buffers. If
    //    handles_map refers to those buffers through a string_view, it dangles as well.
    uintptr_t lm_addr = (uintptr_t)lm & TAG_MASK_UPTR;
    for (uintptr_t p = lm_addr - 512; p < lm_addr + 2048; p += 8) {
        uintptr_t v = *(uintptr_t*)p;
        const char* s = (const char*)(v & TAG_MASK_UPTR);
        if (!in_ranges(rs, rn, (uintptr_t)s)) continue;
        if (strstr(s, "memfd:") || strstr(s, "/proc/self/fd/")) {
            if (!name_real[0] && strstr(s, "memfd:")) {
                strncpy(name_real, s, sizeof(name_real) - 1);
            }
            zap_string(s);
        }
    }

    // 4) wipe copies of both names across the whole heap (such as the std::string key
    //    copies in handles_map)
    int z = zap_string_copies(rs, rn, name_l);
    if (name_real[0]) z += zap_string_copies(rs, rn, name_real);
    __android_log_print(ANDROID_LOG_INFO, "ij2art",
                        "hide_self: unlinked, zapped %d copies", z);
    return res;
}
