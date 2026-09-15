// Library upload backend: staged in a memfd, loaded with dlopen("/proc/self/fd/N").
// The memfd path never exists on disk, so app-domain SELinux rules about
// executing files do not apply; maps shows the module as /memfd:NAME (deleted).
#include "loader.h"
#include "inline_hook.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

namespace {
struct Slot {
    ij2art_lib_info info{};
    int fd = -1;
    void* handle = nullptr;
    uint64_t touched_ms = 0;
};
Slot g_slots[IJ2ART_LIB_SLOTS];
uint32_t g_next_id;

uint64_t now_ms() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000 + uint64_t(ts.tv_nsec) / 1000000;
}
void message(ij2art_rsp& r, int code, const char* text) {
    r.status = code;
    r.len = snprintf(reinterpret_cast<char*>(r.data), sizeof(r.data), "%s", text);
}
void record(ij2art_rsp& r, const Slot& s) {
    memcpy(r.data, &s.info, sizeof(s.info));
    r.len = sizeof(s.info);
    r.retval = s.info.id;
}
Slot* find(uint64_t id) {
    for (auto& s : g_slots) if (id && s.info.id == id) return &s;
    return nullptr;
}
Slot* by_nonce(uint64_t nonce) {
    for (auto& s : g_slots) if (nonce && s.info.nonce == nonce) return &s;
    return nullptr;
}
void close_fd(Slot& s) {
    if (s.fd >= 0) close(s.fd);
    s.fd = -1;
}
void fail(Slot& s, int error) {
    close_fd(s);
    s.info.state = IJ2ART_LIB_FAILED;
    s.info.error = error;
}

bool valid_name(const uint8_t* data, uint64_t len) {
    if (!len || len > IJ2ART_LIB_NAME_MAX) return false;
    for (uint64_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}
// Names must match exactly one module in maps; only live records reserve a name.
bool name_in_use(const char* name) {
    for (auto& s : g_slots) {
        if (!s.info.id) continue;
        if ((s.info.state == IJ2ART_LIB_UPLOADING || s.info.state == IJ2ART_LIB_LOADED) &&
            !strcmp(s.info.name, name)) return true;
    }
    return false;
}

void begin(const ij2art_cmd& c, ij2art_rsp& r) {
    uint64_t nonce = c.args[0], size = c.args[1];
    if (!nonce || size < 64 || size > IJ2ART_LIB_MAX)
        return message(r, IJ2ART_E_LIB_INVALID, "require a nonzero nonce and a 64-byte..4MiB library");
    if (!valid_name(c.data, c.len))
        return message(r, IJ2ART_E_LIB_INVALID, "library name must be 1..48 of [A-Za-z0-9._-]");
    char name[64];
    memcpy(name, c.data, c.len);
    name[c.len] = 0;
    if (Slot* e = by_nonce(nonce)) {
        if (e->info.size != size || strcmp(e->info.name, name))
            return message(r, IJ2ART_E_LIB_STATE, "nonce reused with different size/name; use a fresh nonce");
        return record(r, *e);
    }
    if (name_in_use(name))
        return message(r, IJ2ART_E_LIB_STATE, "library name already in use; pick another --name");
    uint64_t allocated = 0;
    Slot* free_slot = nullptr;
    for (auto& s : g_slots) {
        if (!s.info.id || s.info.state == IJ2ART_LIB_FAILED) {
            if (!free_slot) free_slot = &s;
            continue;
        }
        allocated += s.info.size;
    }
    if (!free_slot || allocated + size > IJ2ART_LIB_TOTAL_MAX)
        return message(r, IJ2ART_E_LIB_LIMIT, "library slot or byte budget exhausted");
    int fd = memfd_create(name, 0); // fd stays open until commit/fail; no exec needed
    if (fd < 0 || ftruncate(fd, static_cast<off_t>(size)) != 0) {
        if (fd >= 0) close(fd);
        return message(r, IJ2ART_E_LIB_LIMIT, "memfd_create/ftruncate failed");
    }
    *free_slot = Slot{};
    free_slot->fd = fd;
    free_slot->touched_ms = now_ms();
    free_slot->info.id = ++g_next_id;
    free_slot->info.nonce = nonce;
    free_slot->info.size = size;
    free_slot->info.state = IJ2ART_LIB_UPLOADING;
    snprintf(free_slot->info.name, sizeof(free_slot->info.name), "%s", name);
    record(r, *free_slot);
}

void chunk(Slot& s, const ij2art_cmd& c, ij2art_rsp& r) {
    if (s.info.state != IJ2ART_LIB_UPLOADING)
        return message(r, IJ2ART_E_LIB_STATE, "record is not uploading; start over with a fresh nonce");
    uint64_t offset = c.args[0];
    if (!c.len || c.len > IJ2ART_CMD_DATA_MAX || offset > s.info.size ||
        c.len > s.info.size - offset)
        return message(r, IJ2ART_E_LIB_INVALID, "invalid chunk bounds");
    if (offset < s.info.received) {
        // Retry of already-received bytes must carry identical content.
        if (c.len > s.info.received - offset)
            return message(r, IJ2ART_E_LIB_STATE, "overlapping chunk conflict");
        uint8_t buf[IJ2ART_CMD_DATA_MAX];
        if (pread(s.fd, buf, c.len, static_cast<off_t>(offset)) != static_cast<ssize_t>(c.len) ||
            memcmp(buf, c.data, c.len))
            return message(r, IJ2ART_E_LIB_STATE, "conflicting retry chunk");
    } else {
        if (offset != s.info.received)
            return message(r, IJ2ART_E_LIB_STATE, "chunks must arrive in order");
        if (pwrite(s.fd, c.data, c.len, static_cast<off_t>(offset)) != static_cast<ssize_t>(c.len))
            return message(r, IJ2ART_E_LIB_IO, "memfd write failed");
        s.info.received += c.len;
    }
    s.touched_ms = now_ms();
    record(r, s);
}

struct BaseCtx {
    const char* path;   // "/proc/self/fd/N" as passed to dlopen
    const char* real;   // readlink of that fd, e.g. "/memfd:NAME (deleted)"
    uint64_t base = 0;
};
int base_cb(dl_phdr_info* info, size_t, void* data) {
    auto* ctx = static_cast<BaseCtx*>(data);
    const char* name = info->dlpi_name ? info->dlpi_name : "";
    if ((ctx->real && !strcmp(name, ctx->real)) || !strcmp(name, ctx->path)) {
        ctx->base = info->dlpi_addr;
        return 1;
    }
    return 0;
}
uint64_t maps_base(const char* real) {
    // Fallback: the kernel always reports the memfd path at the end of the line.
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[1024];
    uint64_t base = 0;
    size_t want = strlen(real);
    while (fgets(line, sizeof(line), f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == ' ')) line[--n] = 0;
        unsigned long start;
        unsigned long offset;
        if (n >= want && !strcmp(line + n - want, real) &&
            sscanf(line, "%lx-%*lx %*4s %lx", &start, &offset) == 2 && offset == 0) {
            base = start;
            break;
        }
    }
    fclose(f);
    return base;
}

void commit(Slot& s, ij2art_rsp& r) {
    if (s.info.state == IJ2ART_LIB_LOADED) return record(r, s); // idempotent retry
    if (s.info.state != IJ2ART_LIB_UPLOADING)
        return message(r, IJ2ART_E_LIB_STATE, "record is not uploading; start over with a fresh nonce");
    if (s.info.received != s.info.size)
        return message(r, IJ2ART_E_LIB_STATE, "upload is incomplete");
    uint8_t eh[20];
    if (pread(s.fd, eh, sizeof(eh), 0) != static_cast<ssize_t>(sizeof(eh)) ||
        memcmp(eh, "\x7f" "ELF", 4) || eh[4] != 2 || eh[5] != 1 ||
        eh[16] != 3 || eh[17] != 0 || eh[18] != 183 || eh[19] != 0) {
        fail(s, IJ2ART_E_LIB_INVALID);
        return message(r, IJ2ART_E_LIB_INVALID, "not an arm64 ELF64 shared object (ET_DYN)");
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", s.fd);
    void* handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        const char* error = dlerror();
        fail(s, IJ2ART_E_LIB_DLOPEN);
        return message(r, IJ2ART_E_LIB_DLOPEN, error ? error : "dlopen failed");
    }
    char real[256];
    ssize_t n = readlink(path, real, sizeof(real) - 1);
    const char* resolved = nullptr;
    if (n > 0) {
        real[n] = 0;
        resolved = real;
    }
    BaseCtx ctx{path, resolved};
    dl_iterate_phdr(base_cb, &ctx);
    close_fd(s); // the linker maps its own references; our fd is no longer needed
    s.handle = handle;
    s.info.handle = reinterpret_cast<uint64_t>(handle);
    s.info.base = ctx.base ? ctx.base : (resolved ? maps_base(resolved) : 0);
    s.info.state = IJ2ART_LIB_LOADED;
    record(r, s);
}

void unload(Slot& s, ij2art_rsp& r) {
    if (s.info.state == IJ2ART_LIB_UNLOADED) return record(r, s); // idempotent
    if (s.info.state != IJ2ART_LIB_LOADED)
        return message(r, IJ2ART_E_LIB_STATE, "only a LOADED library can be unloaded");
    // The registry is this module's only pin (memfd path cannot be NOLOAD'd):
    // dlclose would unmap live hook code. File-backed libraries keep their own
    // references and are unaffected by this check.
    if (ij2art_inline_module_in_use(reinterpret_cast<void*>(s.info.base)))
        return message(r, IJ2ART_E_LIB_STATE,
                       "an active inline hook references this library; remove it first");
    // The caller must quiesce this library's code before unloading (same rule as
    // inline del): dlclose unmaps a never-pinned module immediately.
    if (dlclose(s.handle) != 0) {
        const char* error = dlerror();
        return message(r, IJ2ART_E_LIB_DLOPEN, error ? error : "dlclose failed");
    }
    s.handle = nullptr;
    s.info.handle = 0;
    s.info.state = IJ2ART_LIB_UNLOADED;
    record(r, s);
}
} // namespace

bool ij2art_loader_command(const ij2art_cmd& c, ij2art_rsp& r) {
    switch (c.type) {
    case IJ2ART_CMD_LIB_BEGIN:
        begin(c, r);
        return true;
    case IJ2ART_CMD_LIB_CHUNK:
    case IJ2ART_CMD_LIB_COMMIT:
    case IJ2ART_CMD_LIB_UNLOAD: {
        Slot* s = find(c.addr);
        if (!s) {
            message(r, IJ2ART_E_LIB_NOT_FOUND, "unknown library id in this process");
            return true;
        }
        if (c.type == IJ2ART_CMD_LIB_CHUNK) chunk(*s, c, r);
        else if (c.type == IJ2ART_CMD_LIB_COMMIT) commit(*s, r);
        else unload(*s, r);
        return true;
    }
    case IJ2ART_CMD_LIB_LIST:
        for (const auto& s : g_slots) {
            if (!s.info.id) continue;
            if (r.len > IJ2ART_RSP_DATA_MAX - sizeof(s.info)) { r.flags |= 1; break; }
            memcpy(r.data + r.len, &s.info, sizeof(s.info));
            r.len += sizeof(s.info);
        }
        return true;
    default:
        return false;
    }
}

void ij2art_loader_tick() {
    uint64_t now = now_ms();
    for (auto& s : g_slots) {
        if (s.info.id && s.info.state == IJ2ART_LIB_UPLOADING && now >= s.touched_ms &&
            now - s.touched_ms >= 60000)
            fail(s, IJ2ART_E_LIB_STATE);
    }
}

bool ij2art_loader_owns_base(uint64_t base) {
    for (const auto& s : g_slots) {
        if (s.info.id && s.info.state == IJ2ART_LIB_LOADED && s.info.base &&
            s.info.base == base)
            return true;
    }
    return false;
}
