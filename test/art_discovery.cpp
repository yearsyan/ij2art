// Runs the production parser/decoder/ABI discovery on an actual device ELF.
#include "../payload/art_discovery.h"
#include <cassert>
#include <iostream>

namespace {
std::string debug_path;
bool inflate(const uint8_t*, size_t, std::vector<uint8_t>& out) {
    std::ifstream f(debug_path, std::ios::binary | std::ios::ate);
    auto n = f.tellg(); if (n < 0 || n > 128 * 1024 * 1024) return false;
    out.resize(size_t(n)); f.seekg(0); return bool(f.read(reinterpret_cast<char*>(out.data()), n));
}
}
int main(int argc, char** argv) {
    if (argc != 4) { std::cerr << "usage: art-discovery-test ELF DEBUG_ELF API\n"; return 2; }
    debug_path = argv[2];
    using namespace ij2art;
    art_profile::Discovery d;
    if (!d.elf.open(argv[1], inflate)) { std::cerr << "invalid ELF\n"; return 1; }
    if (!strcmp(argv[3], "decoder")) {
        auto runtime = d.elf.resolve("_ZN3art7Runtime9instance_E");
        auto method = d.elf.resolve("_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE");
        assert(runtime && method);
        auto facts = art_a64::Decoder(d.elf, runtime->rva).inspect(method->rva);
        std::cout << "["; bool comma = false;
        for (const auto& a : facts.accesses) if (a.base.root >= 0 && a.base.root < 8 && !a.base.depth) {
            std::cout << (comma ? "," : "") << "[" << a.base.root << "," << a.offset << "," << a.width << "," << a.store << "]";
            comma = true;
        }
        std::cout << "]\n"; return 0;
    }
    if (!d.inspect(atoi(argv[3]))) { std::cerr << d.error << '\n'; return 1; }
    std::cout << "{\"id\":\"" << d.profile.build_id << "\",\"backend\":\"" << d.profile.name << "\",\"sites\":[";
    for (size_t i = 0; i < d.sites.size(); ++i) std::cout << (i ? "," : "") << d.sites[i].rva;
    std::cout << "],\"patterns\":[";
    for (size_t i = 0; i < d.patterns.size(); ++i) std::cout << (i ? "," : "") << d.patterns[i];
    const auto& l = d.profile.layout;
    std::cout << "],\"layout\":{";
    const std::pair<const char*, size_t> fields[] = {
        {"runtime_threads", l.runtime_threads}, {"runtime_linker", l.runtime_linker},
        {"runtime_jit", l.runtime_jit}, {"runtime_cache", l.runtime_cache},
        {"runtime_instrumentation", l.runtime_instrumentation}, {"runtime_callbacks", l.runtime_callbacks},
        {"instrumentation_pointer", l.instrumentation_pointer},
        {"runtime_debuggable", l.runtime_debuggable}, {"linker_cha", l.linker_cha},
        {"class_status", l.class_status}, {"pool_started", l.pool_started},
        {"pool_waiting", l.pool_waiting}, {"pool_threads", l.pool_threads},
        {"cache_saved", l.cache_saved}, {"cache_zygote", l.cache_zygote},
        {"cache_collecting", l.cache_collecting}, {"cache_zombies", l.cache_zombies},
        {"cache_osr_zombies", l.cache_osr_zombies}, {"visitor_size", l.visitor_size},
        {"gc_section_size", l.gc_section_size},
    };
    bool comma = false;
    for (const auto& f : fields) {
        std::cout << (comma ? "," : "") << '"' << f.first << "\":" << f.second;
        comma = true;
    }
    std::cout << "}}\n";

    // Same normalized name with two addresses must never select an arbitrary
    // LTO clone. Duplicate symbols at the same address are legitimate aliases.
    auto symbol = *d.elf.resolve("_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE");
    d.elf.symbols.push_back(symbol);
    assert(d.inspect(atoi(argv[3])));
    symbol.name += ".__uniq.999.llvm.111"; symbol.rva += 4;
    d.elf.symbols.push_back(symbol);
    assert(!d.inspect(atoi(argv[3])) && d.error.find("ambiguous ART symbol") != std::string::npos);
    d.elf.symbols.pop_back();
    if (auto helper = d.elf.resolve("_ZN3art9ArtMethod18IsImagePointerSizeENS_11PointerSizeE")) {
        auto clone = *helper;
        clone.name += ".llvm.999"; clone.rva += 4;
        d.elf.symbols.push_back(clone);
        assert(!d.inspect(atoi(argv[3])) && d.error.find("ambiguous ART ClassLinker") != std::string::npos);
        d.elf.symbols.pop_back();
    }
    if (auto helper = d.elf.resolve("_ZN3art3jit12JitCodeCache21AddZombieCodeInternalEPNS_9ArtMethodEPKv")) {
        auto clone = *helper;
        clone.name += ".llvm.999"; clone.rva += 4;
        d.elf.symbols.push_back(clone);
        assert(!d.inspect(atoi(argv[3])) && d.error.find("ambiguous ART zombie-code") != std::string::npos);
        d.elf.symbols.pop_back();
    }
    assert(d.inspect(atoi(argv[3])));
    if (d.profile.family == art_profile::Family::ZombieCode) {
        auto original_symbols = d.elf.symbols;
        d.elf.symbols.erase(std::remove_if(d.elf.symbols.begin(), d.elf.symbols.end(), [](const art_elf::Entry& s) {
            for (const auto& c : art_profile::discovery_detail::candidates)
                if (c.symbol == art_profile::Symbol::erase_pointer_set && art_elf::Image::normalized(s.name) == c.name)
                    return true;
            return false;
        }), d.elf.symbols.end());
        assert(!d.inspect(atoi(argv[3])) && d.error.find("requires pointer-set erase") != std::string::npos);
        d.elf.symbols = original_symbols;
        assert(d.inspect(atoi(argv[3])));
        if (!d.profile.site(art_profile::Symbol::jit_mutator_lock).rva) {
            // Android 15 must not silently fall back to the non-zombie backend.
            d.elf.symbols.erase(std::remove_if(d.elf.symbols.begin(), d.elf.symbols.end(), [](const art_elf::Entry& s) {
                return art_elf::Image::normalized(s.name) == "_ZN3art3jit12JitCodeCache21AddZombieCodeInternalEPNS_9ArtMethodEPKv";
            }), d.elf.symbols.end());
            assert(!d.inspect(atoi(argv[3])) && d.error.find("verified ABI rule") != std::string::npos);
            d.elf.symbols = original_symbols;
        }
    }
    d.elf.symbols.erase(std::remove_if(d.elf.symbols.begin(), d.elf.symbols.end(), [](const art_elf::Entry& s) {
        return art_elf::Image::normalized(s.name) == "_ZN3art3jit12JitCodeCache21LookupOsrMethodHeaderEPNS_9ArtMethodE";
    }), d.elf.symbols.end());
    assert(d.inspect(atoi(argv[3]))); // A missing fixture-only operation cannot disable production hooks.
    d.elf.symbols.erase(std::remove_if(d.elf.symbols.begin(), d.elf.symbols.end(), [](const art_elf::Entry& s) {
        return art_elf::Image::normalized(s.name) == "_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE";
    }), d.elf.symbols.end());
    assert(!d.inspect(atoi(argv[3])) && d.error.find("missing ART symbol") != std::string::npos);
    assert(!d.inspect(999));
}
