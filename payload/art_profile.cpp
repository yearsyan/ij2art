#include "art_profile.h"
#include <dlfcn.h>
#include <elf.h>
#include <cstdio>

namespace ij2art::art_profile {
namespace {
#include "art_profiles/symbols14.inc"
#include "art_profiles/symbols16.inc"
#include "art_profiles/patterns16.inc"
static_assert(sizeof(sites14) / sizeof(Site) == static_cast<size_t>(Symbol::Count));
static_assert(sizeof(sites16) / sizeof(Site) == static_cast<size_t>(Symbol::Count));
const Profile profiles[] = {
    {"7bf2886127ae5230f6030d2e8fa42561", "android16-arm64-zombie-code", Family::ZombieCode,
     {/* runtime threads/linker/jit/cache */ 0x250,0x260,0x288,0x290,
      /* instrumentation/callbacks/debuggable/pointer */ 0x330,0x540,0x3e4,true,
      /* linker CHA/class status */ 0x270,0x68,
      /* pool started/waiting/threads */ 0x80,0x88,0x90,
      /* cache saved/zygote/collecting */ 0x340,0x3b8,0x3f0,
      /* cache zombies/OSR zombies */ 0x370,0x408,
      /* visitor/GC section size */ 0x1f0,24},
     {}, sites16, patterns16, sizeof(patterns16) / sizeof(uint32_t)},
    {"1baa085e52462906909d6dfe1b6332e2", "android14-arm64-locked-code", Family::LockedCode,
     {/* runtime threads/linker/jit/cache */ 0x248,0x258,0x280,0x288,
      /* instrumentation/callbacks/debuggable/pointer */ 0x328,0x698,0x564,false,
      /* linker CHA/class status */ 0x208,0x70,
      /* pool started/waiting/threads */ 0x78,0x80,0x88,
      /* cache saved/zygote/collecting */ 0x328,0x370,0x3a8,
      /* no zombie sets */ 0,0,
      /* visitor/GC section size */ 0x1f0,24},
     {}, sites14, nullptr, 0},
};
}
const Profile* find(const char* id) {
    for (const auto& p : profiles) if (!strcmp(p.build_id, id)) return &p;
    return nullptr;
}
const Profile* from_base(uintptr_t base) {
    if (!base) return nullptr;
    const auto* eh = reinterpret_cast<const Elf64_Ehdr*>(base);
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS64) return nullptr;
    auto* ph = reinterpret_cast<const Elf64_Phdr*>(base + eh->e_phoff);
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_NOTE) continue;
        const auto* pos = reinterpret_cast<const unsigned char*>(base + ph[i].p_vaddr);
        const auto* end = pos + ph[i].p_memsz;
        while (size_t(end - pos) >= sizeof(Elf64_Nhdr)) {
            Elf64_Nhdr n; memcpy(&n, pos, sizeof(n)); pos += sizeof(n);
            size_t ns = (size_t(n.n_namesz) + 3) & ~size_t(3);
            size_t ds = (size_t(n.n_descsz) + 3) & ~size_t(3);
            if (ns > size_t(end - pos) || ds > size_t(end - pos) - ns) break;
            if (n.n_type == NT_GNU_BUILD_ID && n.n_namesz == 4 && !memcmp(pos, "GNU", 4) && n.n_descsz <= 32) {
                char id[65]{};
                for (size_t j = 0; j < n.n_descsz; ++j) snprintf(id + j * 2, 3, "%02x", pos[ns + j]);
                return find(id);
            }
            pos += ns + ds;
        }
    }
    return nullptr;
}
bool validate(const Profile& p, uintptr_t base, char* error, size_t size) {
    if (from_base(base) != &p) {
        snprintf(error, size, "ART profile/build-id mismatch"); return false;
    }
    for (size_t i = 0; i < static_cast<size_t>(Symbol::Count); ++i) {
        const Site& s = p.sites[i];
        if (!s.rva) continue;
        void* address = reinterpret_cast<void*>(base + s.rva);
        void* resolved = dlsym(RTLD_DEFAULT, s.name);
        Dl_info info{};
        if (resolved && dladdr(resolved, &info) && reinterpret_cast<uintptr_t>(info.dli_fbase) == base && resolved != address) {
            snprintf(error, size, "ART symbol/profile mismatch: %s", s.name); return false;
        }
        // Guard installation validates its own sites, allowing retry after a
        // partial installation without treating our own patches as mismatches.
        if (i < static_cast<size_t>(Symbol::optimized) && s.prologue[0] &&
            memcmp(address, s.prologue, sizeof(s.prologue))) {
            snprintf(error, size, "ART ABI prologue mismatch: %s", s.name); return false;
        }
    }
    return true;
}
}
