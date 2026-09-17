#pragma once
#include "art_elf.h"
#include <array>
#include <deque>
#include <set>

// A deliberately small data-flow decoder, not an emulator. Unknown writes and
// disagreeing control-flow paths erase provenance; they never guess an offset.
namespace ij2art::art_a64 {
constexpr int Unknown = -1, Constant = -2, Runtime = 8, Stack = 9;
struct Value {
    int root = Unknown, depth = 0;
    std::array<int64_t, 4> path{};
    int64_t offset = 0;
    bool operator==(const Value& b) const { return root == b.root && depth == b.depth && path == b.path && offset == b.offset; }
    static Value constant(int64_t n) { Value v; v.root = Constant; v.offset = n; return v; }
};
struct Access { Value base; int64_t offset; unsigned width; bool store; };
struct Facts {
    std::vector<Access> accesses;
    std::vector<Value> addresses;
    bool field(int root, std::initializer_list<int64_t> path, int64_t offset, unsigned width, bool store = false) const {
        for (const auto& a : accesses) if (a.base.root == root && a.base.depth == int(path.size()) &&
            std::equal(path.begin(), path.end(), a.base.path.begin()) && a.offset == offset &&
            a.width == width && a.store == store) return true;
        return false;
    }
    bool address(int root, int64_t offset) const {
        for (const auto& a : addresses) if (a.root == root && !a.depth && a.offset == offset) return true;
        return false;
    }
};
using State = std::array<Value, 32>;
inline int64_t sign(uint64_t n, unsigned bits) { return int64_t(n << (64 - bits)) >> (64 - bits); }
class Decoder {
    const art_elf::Image& elf;
    uint64_t runtime;
    struct Step { State regs; int64_t branch = -1; bool conditional = false, done = false; };
    Step step(uint64_t pc, uint32_t w, const State& in, Facts* facts) const {
        Step s{in}; auto& r = s.regs;
        unsigned d = w & 31, n = (w >> 5) & 31, m = (w >> 16) & 31;
        auto address = [&](Value v, int64_t off) { if (v.root != Unknown) v.offset += off; return v; };
        auto mem = [&](unsigned reg, Value base, int64_t off, unsigned width, bool store, bool simd) {
            if (base.root == Unknown) { if (!store && !simd && reg != 31) r[reg] = {}; return; }
            off += base.offset; base.offset = 0;
            if (facts) facts->accesses.push_back({base, off, width, store});
            if (store || simd || reg == 31) return;
            Value loaded;
            if (width == 8 && base.root == Constant) {
                if (uint64_t(off) == runtime) loaded.root = Runtime;
                else if (auto p = elf.pointer(uint64_t(off))) loaded = Value::constant(int64_t(p));
            } else if (base.root >= 0 && base.root != Stack && base.depth < 4) {
                loaded = base; loaded.path[loaded.depth++] = off;
            }
            r[reg] = loaded;
        };
        if ((w & 0x9f000000) == 0x90000000 || (w & 0x9f000000) == 0x10000000) {
            int64_t imm = sign(((w >> 5) & 0x7ffff) << 2 | ((w >> 29) & 3), 21);
            bool page = (w & 0x80000000) != 0;
            r[d] = Value::constant(int64_t(page ? pc & ~uint64_t(4095) : pc) + (page ? imm * 4096 : imm));
        } else if ((w & 0xffe0ffe0) == 0xaa0003e0) { // MOV Xd, Xm
            r[d] = m == 31 ? Value::constant(0) : r[m];
        } else if ((w & 0x7f000000) == 0x11000000) { // ADD immediate, without flags
            int64_t imm = (w >> 10) & 0xfff; if (w & (1u << 22)) imm <<= 12;
            r[d] = (w >> 31) ? address(r[n], imm) : Value{};
            if (facts && r[d].root != Unknown) facts->addresses.push_back(r[d]);
        } else if ((w & 0x7f000000) == 0x51000000) { // SUB immediate
            int64_t imm = (w >> 10) & 0xfff; if (w & (1u << 22)) imm <<= 12;
            r[d] = (w >> 31) ? address(r[n], -imm) : Value{};
        } else if ((w & 0x3b000000) == 0x39000000) { // unsigned load/store, including SIMD
            bool simd = w & (1u << 26);
            bool store = simd ? !(w & (1u << 22)) : ((w >> 22) & 3) == 0;
            unsigned scale = w >> 30; if (simd && (w & (1u << 23))) scale = 4;
            // Integer opc=2/3 are sign-extending loads, not stores. Size=3,
            // opc=2 is PRFM and does not read an object field into a register.
            if (simd || scale != 3 || ((w >> 22) & 3) < 2)
                mem(d, r[n], int64_t((w >> 10) & 0xfff) << scale, 1u << scale, store, simd);
        } else if ((w & 0x3b200000) == 0x38000000) { // unscaled/pre/post indexed
            bool simd = w & (1u << 26);
            bool store = simd ? !(w & (1u << 22)) : ((w >> 22) & 3) == 0;
            unsigned scale = w >> 30; if (simd && (w & (1u << 23))) scale = 4;
            unsigned mode = (w >> 10) & 3; int64_t imm = sign((w >> 12) & 511, 9);
            Value base = r[n];
            if (simd || scale != 3 || ((w >> 22) & 3) < 2)
                mem(d, base, mode == 1 ? 0 : imm, 1u << scale, store, simd);
            if (mode == 1 || mode == 3) r[n] = address(base, imm);
        } else if ((w & 0x3a000000) == 0x28000000) { // load/store pair
            bool simd = w & (1u << 26), store = !(w & (1u << 22));
            unsigned scale = simd ? 2 + (w >> 30) : 2 + (w >> 31);
            unsigned width = 1u << scale, mode = (w >> 23) & 3, d2 = (w >> 10) & 31;
            int64_t imm = sign((w >> 15) & 127, 7) * width; Value base = r[n];
            mem(d, base, mode == 1 ? 0 : imm, width, store, simd);
            mem(d2, base, (mode == 1 ? 0 : imm) + width, width, store, simd);
            if (mode == 1 || mode == 3) r[n] = address(base, imm);
        } else if ((w & 0x7c000000) == 0x14000000) {
            if (w >> 31) { for (unsigned i = 0; i <= 18; ++i) r[i] = {}; r[30] = {}; }
            else { s.branch = int64_t(pc) + sign(w & 0x3ffffff, 26) * 4; s.done = true; }
        } else if ((w & 0xff000010) == 0x54000000 || (w & 0x7e000000) == 0x34000000) {
            s.branch = int64_t(pc) + sign((w >> 5) & 0x7ffff, 19) * 4; s.conditional = true;
        } else if ((w & 0x7e000000) == 0x36000000) {
            s.branch = int64_t(pc) + sign((w >> 5) & 0x3fff, 14) * 4; s.conditional = true;
        } else if ((w & 0xfffffc1f) == 0xd63f0000) { // BLR
            for (unsigned i = 0; i <= 18; ++i) r[i] = {}; r[30] = {};
        } else if ((w & 0xfffffc1f) == 0xd65f0000 || (w & 0xfffffc1f) == 0xd61f0000 || !w) {
            s.done = true;
        } else if ((w & 0xfffff01f) == 0xd503201f || (w & 0x1e000000) == 0x0e000000) {
            // HINT/PAC/BTI and SIMD arithmetic do not change object GPRs.
        } else if (d != 31) {
            // Most remaining data-processing instructions write Rd. Erasing
            // it also handles loads/atomics not recognized above conservatively.
            r[d] = {};
        }
        return s;
    }
    void analyze(uint64_t entry, const State& initial, Facts& facts, unsigned depth) const {
        auto symbol = elf.function(entry);
        if (!symbol || symbol->size > 65536 || symbol->size % 4 || !depth) return;
        const uint8_t* code = elf.bytes(entry, symbol->size, true); if (!code) return;
        size_t count = symbol->size / 4;
        std::vector<State> states(count); std::vector<bool> seen(count);
        std::deque<size_t> queue;
        auto merge = [&](uint64_t pc, const State& state) {
            if (pc < entry || (pc - entry) % 4 || pc - entry >= symbol->size) return;
            size_t index = (pc - entry) / 4; bool changed = !seen[index];
            if (!seen[index]) { states[index] = state; seen[index] = true; }
            else for (size_t reg = 0; reg < 32; ++reg) {
                if (!(states[index][reg] == state[reg]) && states[index][reg].root != Unknown) {
                    states[index][reg] = {}; changed = true;
                }
            }
            if (changed) queue.push_back(index);
        };
        merge(entry, initial);
        size_t budget = count * 64;
        while (!queue.empty() && budget--) {
            size_t index = queue.front(); queue.pop_front(); uint32_t w;
            memcpy(&w, code + index * 4, 4);
            auto next = step(entry + index * 4, w, states[index], nullptr);
            if (next.branch >= 0) merge(uint64_t(next.branch), next.regs);
            if (!next.done) merge(entry + (index + 1) * 4, next.regs);
        }
        if (!queue.empty()) return;
        for (size_t i = 0; i < count; ++i) if (seen[i]) {
            uint32_t w; memcpy(&w, code + i * 4, 4);
            auto next = step(entry + i * 4, w, states[i], &facts);
            if (next.done && next.branch >= 0 && (uint64_t(next.branch) < entry || uint64_t(next.branch) >= entry + symbol->size))
                analyze(uint64_t(next.branch), next.regs, facts, depth - 1);
        }
    }
public:
    Decoder(const art_elf::Image& image, uint64_t runtime_rva) : elf(image), runtime(runtime_rva) {}
    Facts inspect(uint64_t entry) const {
        State initial{}; for (int i = 0; i < 8; ++i) initial[i].root = i;
        initial[31].root = Stack; Facts facts; analyze(entry, initial, facts, 3); return facts;
    }
};
}
