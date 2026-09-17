#include "art_discovery.h"
#include "../third_party/shadowhook/third_party/xdl/xdl_lzma.h"
#include <dlfcn.h>
#include <elf.h>
#include <jni.h>
#include <link.h>
#include <sys/system_properties.h>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <numeric>

namespace ij2art::art_profile {
namespace {
std::mutex discovery_mutex;
std::unique_ptr<Discovery> discovered;
uintptr_t discovered_base;
struct Range { uintptr_t begin, end; bool executable; };
struct Mapped {
    uintptr_t base;
    std::string path, id;
    std::vector<Range> ranges;
    bool contains(uintptr_t address, size_t size, bool exec = false) const {
        for (const auto& r : ranges) if ((!exec || r.executable) && address >= r.begin &&
            address <= r.end && size <= r.end - address) return true;
        return false;
    }
};
bool mapped_art(uintptr_t base, Mapped& mapped) {
    mapped.base = base;
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* raw) {
        auto& m = *static_cast<Mapped*>(raw);
        if (info->dlpi_addr != m.base || !strstr(info->dlpi_name, "/libart.so")) return 0;
        m.path = info->dlpi_name;
        for (size_t i = 0; i < info->dlpi_phnum; ++i) {
            const auto& p = info->dlpi_phdr[i];
            if (p.p_type == PT_LOAD && (p.p_flags & PF_R))
                m.ranges.push_back({m.base + p.p_vaddr, m.base + p.p_vaddr + p.p_memsz, bool(p.p_flags & PF_X)});
        }
        for (size_t i = 0; i < info->dlpi_phnum; ++i) {
            const auto& p = info->dlpi_phdr[i];
            if (p.p_type != PT_NOTE || !m.contains(m.base + p.p_vaddr, p.p_memsz)) continue;
            const auto* pos = reinterpret_cast<const unsigned char*>(m.base + p.p_vaddr);
            const auto* end = pos + p.p_memsz;
            while (size_t(end - pos) >= sizeof(Elf64_Nhdr)) {
                Elf64_Nhdr n; memcpy(&n, pos, sizeof(n)); pos += sizeof(n);
                size_t ns = (size_t(n.n_namesz) + 3) & ~size_t(3), ds = (size_t(n.n_descsz) + 3) & ~size_t(3);
                if (ns > size_t(end - pos) || ds > size_t(end - pos) - ns) break;
                if (n.n_type == NT_GNU_BUILD_ID && n.n_namesz == 4 && !memcmp(pos, "GNU", 4) && n.n_descsz <= 64) {
                    char id[129]{};
                    for (size_t j = 0; j < n.n_descsz; ++j) snprintf(id + j * 2, 3, "%02x", pos[ns + j]);
                    m.id = id;
                }
                pos += ns + ds;
            }
        }
        return 1;
    }, &mapped);
    return !mapped.path.empty() && !mapped.id.empty();
}
bool inflate(const uint8_t* data, size_t size, std::vector<uint8_t>& out) {
    uint8_t* bytes = nullptr; size_t length = 0;
    if (xdl_lzma_decompress(const_cast<uint8_t*>(data), size, &bytes, &length) != 0) return false;
    bool valid = bytes && length <= 128 * 1024 * 1024;
    if (valid) out.assign(bytes, bytes + length);
    free(bytes); return valid;
}
struct Memory {
    std::vector<Range> ranges;
    Memory() {
        FILE* file = fopen("/proc/self/maps", "re"); if (!file) return;
        char line[1024], mode[5]; unsigned long begin, end;
        while (fgets(line, sizeof(line), file)) if (sscanf(line, "%lx-%lx %4s", &begin, &end, mode) == 3 && mode[0] == 'r')
            ranges.push_back({begin, end, mode[2] == 'x'});
        fclose(file);
    }
    bool readable(uintptr_t p, size_t size, bool executable = false) const {
        // Android's native heap can return top-byte-tagged pointers. /proc/maps
        // describes untagged ranges; preserve the original tag for the read.
        p &= UINT64_C(0x00ffffffffffffff);
        for (const auto& r : ranges) if ((!executable || r.executable) && p >= r.begin && p <= r.end && size <= r.end - p) return true;
        return false;
    }
    template<class T> bool read(uintptr_t p, T& out) const {
        if (!readable(p, sizeof(T))) return false;
        memcpy(&out, reinterpret_cast<const void*>(p), sizeof(T)); return true;
    }
};
bool probe_methods(Discovery& d, const Mapped& mapped) {
    using GetVMs = jint (*)(JavaVM**, jsize, jsize*);
    // The payload's linker namespace need not expose libart to dlsym.
    auto exported = d.elf.resolve("JNI_GetCreatedJavaVMs");
    if (!exported || !mapped.contains(mapped.base + exported->rva, 16, true) ||
        !d.elf.bytes(exported->rva, 16, true) || memcmp(reinterpret_cast<void*>(mapped.base + exported->rva),
            d.elf.bytes(exported->rva, 16, true), 16)) return d.fail("JNI_GetCreatedJavaVMs export probe failed");
    auto get = reinterpret_cast<GetVMs>(mapped.base + exported->rva);
    JavaVM* vm = nullptr; jsize count = 0; JNIEnv* env = nullptr;
    if (!get || get(&vm, 1, &count) != JNI_OK || count != 1 || !vm ||
        vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK)
        return d.fail("ArtMethod probe requires an attached JNI thread");
    if (env->PushLocalFrame(32) != JNI_OK) { env->ExceptionClear(); return d.fail("ArtMethod probe local frame unavailable"); }
    struct Frame { JNIEnv* env; ~Frame() { env->PopLocalFrame(nullptr); } } frame{env};
    auto java_fail = [&]() { env->ExceptionClear(); return d.fail("ArtMethod reflection fields/constructors unavailable"); };
    jclass executable = env->FindClass("java/lang/reflect/Executable");
    if (!executable) return java_fail();
    auto pointer = env->GetFieldID(executable, "artMethod", "J");
    if (!pointer) return java_fail();
    auto access = env->GetFieldID(executable, "accessFlags", "I");
    if (!access) return java_fail();
    jclass throwable = env->FindClass("java/lang/Throwable");
    if (!throwable) return java_fail();
    constexpr const char* signatures[] = {"()V", "(Ljava/lang/String;)V", "(Ljava/lang/Throwable;)V",
        "(Ljava/lang/String;Ljava/lang/Throwable;)V", "(Ljava/lang/String;Ljava/lang/Throwable;ZZ)V"};
    struct Sample { uintptr_t address; uint32_t flags; };
    std::vector<Sample> samples;
    for (const auto* signature : signatures) {
        auto method = env->GetMethodID(throwable, "<init>", signature);
        if (!method) return java_fail();
        jobject reflected = env->ToReflectedMethod(throwable, method, false);
        if (!reflected) return java_fail();
        samples.push_back({uintptr_t(env->GetLongField(reflected, pointer)), uint32_t(env->GetIntField(reflected, access))});
        if (env->ExceptionCheck()) return java_fail();
    }
    std::sort(samples.begin(), samples.end(), [](const Sample& a, const Sample& b) { return a.address < b.address; });
    size_t stride = 0;
    for (size_t i = 1; i < samples.size(); ++i) stride = std::gcd(stride, samples[i].address - samples[i - 1].address);
    if (stride < 24 || stride > 128 || stride % 8) return d.fail("ArtMethod constructor spacing is unsupported");
    Memory memory;
    for (const auto& s : samples) if (!s.address || !memory.readable(s.address, stride))
        return d.fail("ArtMethod sample lies outside readable memory");
    std::vector<size_t> flag_offsets;
    for (size_t off = 0; off + 4 <= stride - 16; off += 4) {
        bool matches = true;
        for (const auto& s : samples) {
            uint32_t value = 0; memory.read(s.address + off, value);
            matches &= value == s.flags;
        }
        if (matches) flag_offsets.push_back(off);
    }
    if (flag_offsets.size() != 1) return d.fail("ArtMethod accessFlags probe is ambiguous");
    auto& m = d.profile.method;
    m.size = stride; m.flags = flag_offsets[0]; m.quick = stride - 8; m.data = stride - 16;
    art_a64::Decoder decoder(d.elf, d.profile.site(Symbol::runtime).rva);
    auto copy = decoder.inspect(d.profile.site(Symbol::copy).rva);
    auto oat = d.elf.resolve("_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm");
    if (!oat || !copy.field(1, {}, m.flags, 4) || !copy.field(1, {}, m.declaring_class, 4) ||
        !decoder.inspect(oat->rva).field(0, {}, m.quick, 8)) return d.fail("ArtMethod live layout disagrees with ART field accesses");
    for (const auto& s : samples) {
        uintptr_t entry = 0; uint32_t declaring = 0;
        memory.read(s.address + m.quick, entry); memory.read(s.address + m.declaring_class, declaring);
        if (!memory.readable(entry, 4, true) || !declaring || !memory.readable(declaring, 8))
            return d.fail("ArtMethod declaring class/quick entry probe failed");
    }
    auto& l = d.profile.layout;
    uintptr_t runtime = 0, linker = 0, cha = 0, jit = 0, cache = 0, owned_cache = 0, threads = 0, callbacks = 0;
    if (!memory.read(mapped.base + d.profile.site(Symbol::runtime).rva, runtime) || !runtime)
        return d.fail("ART Runtime instance probe failed");
    if (!memory.read(runtime + l.runtime_threads, threads) || !memory.readable(threads, 8))
        return d.fail("ART Runtime thread-list pointer probe failed");
    if (!memory.read(runtime + l.runtime_linker, linker) || !linker ||
        !memory.read(linker + l.linker_cha, cha) || !memory.readable(cha, 32))
        return d.fail("ART ClassLinker/CHA pointer probe failed");
    if (!memory.read(runtime + l.runtime_callbacks, callbacks) || !memory.readable(callbacks, 8))
        return d.fail("ART Runtime callbacks pointer probe failed");
    if (!memory.read(runtime + l.runtime_jit, jit) || !memory.read(runtime + l.runtime_cache, cache))
        return d.fail("ART Runtime JIT/cache pointer probe failed");
    if (jit && (!memory.read(jit + 8, owned_cache) || owned_cache != cache))
        return d.fail("ART Runtime/Jit code-cache ownership mismatch");
    uintptr_t instrumentation = runtime + l.runtime_instrumentation;
    if (l.instrumentation_pointer && !memory.read(instrumentation, instrumentation)) return d.fail("ART instrumentation pointer unreadable");
    uint32_t level = 0, debug = 0;
    if (!memory.read(instrumentation + 4, level) || level > 2 ||
        !memory.read(runtime + l.runtime_debuggable, debug) || debug > 2)
        return d.fail("ART instrumentation/debug state probe failed");
    return true;
}
}
const Profile* discover(uintptr_t base, char* error, size_t size) {
    std::lock_guard<std::mutex> guard(discovery_mutex);
    auto fail = [&](const std::string& reason) -> const Profile* { if (size) snprintf(error, size, "%s", reason.c_str()); return nullptr; };
    if (discovered) return base == discovered_base ? &discovered->profile : fail("ART load base changed after discovery");
    Mapped mapped{};
    if (!base || !mapped_art(base, mapped)) return fail("loaded libart identity unavailable");
    auto d = std::make_unique<Discovery>();
    if (!d->elf.open(mapped.path.c_str(), inflate)) return fail("ART ELF symbols/.gnu_debugdata unavailable or malformed");
    if (d->elf.id != mapped.id) return fail("loaded ART/file build-ID mismatch");
    char sdk[PROP_VALUE_MAX]{}; __system_property_get("ro.build.version.sdk", sdk);
    if (!d->inspect(atoi(sdk))) return fail(d->error);
    for (const auto& s : d->sites) if (s.rva && !mapped.contains(base + s.rva, s.prologue[0] ? 16 : 8, s.prologue[0] != 0))
        return fail(std::string("ART symbol outside mapped segment: ") + s.name);
    if (!probe_methods(*d, mapped)) return fail(d->error);
    // Keep only the small immutable bindings; the full ELF/debug symbol image
    // is not needed once probes finish and must not remain pinned in every app.
    d->elf = {};
    discovered_base = base; discovered = std::move(d);
    return &discovered->profile;
}
const Profile* from_base(uintptr_t base) { char error[512]; return discover(base, error, sizeof(error)); }
bool validate(const Profile& p, uintptr_t base, char* error, size_t size) {
    Mapped mapped{};
    if (!mapped_art(base, mapped) || mapped.id != p.build_id) {
        snprintf(error, size, "loaded ART/file identity changed"); return false;
    }
    for (size_t i = 0; i < static_cast<size_t>(Symbol::Count); ++i) {
        const Site& s = p.sites[i]; if (!s.rva) continue;
        void* address = reinterpret_cast<void*>(base + s.rva);
        if (!mapped.contains(base + s.rva, s.prologue[0] ? 16 : 8, s.prologue[0] != 0)) {
            snprintf(error, size, "ART symbol mapping changed: %s", s.name); return false;
        }
        void* resolved = dlsym(RTLD_DEFAULT, s.name); Dl_info info{};
        if (resolved && dladdr(resolved, &info) && reinterpret_cast<uintptr_t>(info.dli_fbase) == base && resolved != address) {
            snprintf(error, size, "ART exported/ELF symbol mismatch: %s", s.name); return false;
        }
        // Entry guards validate their own sites, including retries after partial
        // installation. All other executable bindings must still match the file.
        if ((i < static_cast<size_t>(Symbol::optimized) || i >= static_cast<size_t>(Symbol::emplace_pointer_set)) &&
            s.prologue[0] && memcmp(address, s.prologue, sizeof(s.prologue))) {
            snprintf(error, size, "ART live/file prologue mismatch: %s", s.name); return false;
        }
    }
    return true;
}
}
