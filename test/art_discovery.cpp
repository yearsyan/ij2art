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
    std::cout << "]}\n";

    // Same normalized name with two addresses must never select an arbitrary
    // LTO clone. Duplicate symbols at the same address are legitimate aliases.
    auto symbol = *d.elf.resolve("_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE");
    d.elf.symbols.push_back(symbol);
    assert(d.inspect(atoi(argv[3])));
    symbol.name += ".__uniq.999.llvm.111"; symbol.rva += 4;
    d.elf.symbols.push_back(symbol);
    assert(!d.inspect(atoi(argv[3])) && d.error.find("ambiguous ART symbol") != std::string::npos);
    d.elf.symbols.pop_back();
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
