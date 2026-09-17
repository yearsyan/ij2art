#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

// Bounded, read-only ELF64 reader. Kept independent of Android headers so the
// same symbol/ABI discovery runs in host tests against device ELF fixtures.
namespace ij2art::art_elf {
struct Header {
    uint8_t ident[16]; uint16_t type, machine; uint32_t version;
    uint64_t entry, phoff, shoff; uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct Program { uint32_t type, flags; uint64_t offset, va, pa, filesz, memsz, align; };
struct Section { uint32_t name, type; uint64_t flags, addr, offset, size; uint32_t link, info; uint64_t align, entsize; };
struct Symbol { uint32_t name; uint8_t info, other; uint16_t section; uint64_t value, size; };
struct Rela { uint64_t offset, info; int64_t addend; };
static_assert(sizeof(Header) == 64 && sizeof(Program) == 56 && sizeof(Section) == 64 && sizeof(Symbol) == 24);
struct Entry { std::string name; uint64_t rva, size; uint8_t type; };
using Inflate = bool (*)(const uint8_t*, size_t, std::vector<uint8_t>&);
class Image {
    std::vector<uint8_t> data_;
    std::vector<Program> programs_;
    std::map<uint64_t, uint64_t> relocations_;
    template<class T> static bool get(const std::vector<uint8_t>& b, size_t off, T& out) {
        if (off > b.size() || sizeof(T) > b.size() - off) return false;
        memcpy(&out, b.data() + off, sizeof(T)); return true;
    }
    static bool region(const std::vector<uint8_t>& b, uint64_t off, uint64_t size) {
        return off <= b.size() && size <= b.size() - off;
    }
    static std::string string(const std::vector<uint8_t>& b, const Section& s, size_t off) {
        if (off >= s.size || !region(b, s.offset, s.size)) return {};
        auto p = reinterpret_cast<const char*>(b.data() + s.offset + off);
        const char* end = static_cast<const char*>(memchr(p, 0, s.size - off));
        return end ? std::string(p, end) : std::string();
    }
    bool parse(const std::vector<uint8_t>& b, Inflate inflate, bool debug) {
        Header h{};
        if (!get(b, 0, h) || memcmp(h.ident, "\177ELF\2\1", 6) || h.machine != 183 ||
            h.shentsize != sizeof(Section) || !h.shnum || h.shstrndx >= h.shnum ||
            !region(b, h.shoff, uint64_t(h.shnum) * sizeof(Section))) return false;
        std::vector<Section> sections(h.shnum);
        memcpy(sections.data(), b.data() + h.shoff, sections.size() * sizeof(Section));
        for (const auto& s : sections) {
            if (s.type == 2 || s.type == 11) {
                if (s.entsize != sizeof(Symbol) || s.size % sizeof(Symbol) || s.link >= sections.size() ||
                    !region(b, s.offset, s.size)) return false;
                for (size_t pos = 0; pos < s.size; pos += sizeof(Symbol)) {
                    Symbol sym{}; get(b, s.offset + pos, sym);
                    if (!sym.section || !sym.value) continue;
                    auto name = string(b, sections[s.link], sym.name);
                    if (!name.empty()) symbols.push_back({std::move(name), sym.value, sym.size, uint8_t(sym.info & 15)});
                }
            } else if (!debug && s.type == 4) {
                if (s.entsize != sizeof(Rela) || s.size % sizeof(Rela) || s.link >= sections.size() ||
                    !region(b, s.offset, s.size)) return false;
                const auto& table = sections[s.link];
                for (size_t pos = 0; pos < s.size; pos += sizeof(Rela)) {
                    Rela r{}; get(b, s.offset + pos, r);
                    uint32_t kind = uint32_t(r.info), index = uint32_t(r.info >> 32);
                    if (kind == 1027) relocations_[r.offset] = uint64_t(r.addend);
                    else if (kind == 1025 || kind == 1026 || kind == 257) {
                        Symbol sym{};
                        if (table.entsize != sizeof(Symbol) || (uint64_t(index) + 1) * sizeof(Symbol) > table.size ||
                            !get(b, table.offset + uint64_t(index) * sizeof(Symbol), sym)) return false;
                        if (sym.section && sym.value) relocations_[r.offset] = sym.value + r.addend;
                    }
                }
            } else if (!debug && string(b, sections[h.shstrndx], s.name) == ".gnu_debugdata") {
                if (!region(b, s.offset, s.size) || s.size > 32 * 1024 * 1024 || !inflate) return false;
                std::vector<uint8_t> unpacked;
                if (!inflate(b.data() + s.offset, s.size, unpacked) || unpacked.size() > 128 * 1024 * 1024 ||
                    !parse(unpacked, nullptr, true)) return false;
            }
        }
        return true;
    }
public:
    std::vector<Entry> symbols;
    std::string id;
    bool open(const char* path, Inflate inflate) {
        *this = Image{};
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        auto length = stream.tellg();
        if (length < 64 || length > 128 * 1024 * 1024) return false;
        data_.resize(size_t(length)); stream.seekg(0);
        if (!stream.read(reinterpret_cast<char*>(data_.data()), length)) return false;
        Header h{}; get(data_, 0, h);
        if (h.phentsize != sizeof(Program) || h.phnum > 256 ||
            !region(data_, h.phoff, uint64_t(h.phnum) * sizeof(Program))) return false;
        programs_.resize(h.phnum);
        memcpy(programs_.data(), data_.data() + h.phoff, programs_.size() * sizeof(Program));
        for (const auto& p : programs_) {
            if (!region(data_, p.offset, p.filesz)) return false;
            if (p.type != 4) continue;
            for (uint64_t pos = p.offset; pos + 12 <= p.offset + p.filesz;) {
                uint32_t n[3]; memcpy(n, data_.data() + pos, 12);
                uint64_t names = (uint64_t(n[0]) + 3) & ~uint64_t(3), desc = (uint64_t(n[1]) + 3) & ~uint64_t(3);
                if (12 + names + desc > p.offset + p.filesz - pos) return false;
                if (n[2] == 3 && n[0] == 4 && !memcmp(data_.data() + pos + 12, "GNU", 4) && n[1] <= 64) {
                    constexpr char hex[] = "0123456789abcdef";
                    for (uint32_t i = 0; i < n[1]; ++i) {
                        auto c = data_[pos + 12 + names + i]; id += hex[c >> 4]; id += hex[c & 15];
                    }
                }
                pos += 12 + names + desc;
            }
        }
        if (!parse(data_, inflate, false)) return false;
        std::sort(symbols.begin(), symbols.end(), [](const Entry& a, const Entry& b) { return a.name < b.name; });
        return !id.empty() && !symbols.empty();
    }
    static std::string normalized(const std::string& name) {
        size_t end = std::min(name.find(".__uniq."), name.find(".llvm."));
        return name.substr(0, end);
    }
    const Entry* resolve(const char* name, bool* ambiguous = nullptr) const {
        if (ambiguous) *ambiguous = false;
        const Entry* found = nullptr;
        for (const auto& sym : symbols) if (sym.name == name || normalized(sym.name) == name) {
            if (found && found->rva != sym.rva) { if (ambiguous) *ambiguous = true; return nullptr; }
            found = &sym;
        }
        return found;
    }
    const uint8_t* bytes(uint64_t rva, size_t n, bool executable = false) const {
        for (const auto& p : programs_) if (p.type == 1 && (!executable || (p.flags & 1)) &&
            rva >= p.va && rva - p.va <= p.filesz && n <= p.filesz - (rva - p.va))
            return data_.data() + p.offset + (rva - p.va);
        return nullptr;
    }
    uint64_t pointer(uint64_t rva) const {
        auto it = relocations_.find(rva); if (it != relocations_.end()) return it->second;
        uint64_t value = 0; if (auto p = bytes(rva, 8)) memcpy(&value, p, 8); return value;
    }
    const Entry* function(uint64_t rva) const {
        for (const auto& s : symbols) if (s.rva == rva && s.type == 2 && s.size) return &s;
        return nullptr;
    }
};
}
