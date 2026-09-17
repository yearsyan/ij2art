#pragma once
#include "art_a64.h"
#include "art_profile.h"
#include <cstdio>

namespace ij2art::art_profile {
namespace discovery_detail {
#include "art_symbols.inc"
inline bool data_symbol(Symbol s) {
    return s == Symbol::runtime || s == Symbol::thread_list_lock || s == Symbol::jit_lock ||
           s == Symbol::jit_mutator_lock || s == Symbol::cha_lock;
}
inline bool fixture_only(Symbol s) {
    switch (s) {
        case Symbol::add_compile_task: case Symbol::add_method_callback:
        case Symbol::remove_method_callback: case Symbol::lookup_osr:
        case Symbol::insert_pointer_set: case Symbol::add_dependency:
        case Symbol::emplace_pointer_set: case Symbol::emplace_dependency:
        case Symbol::append_dependency: case Symbol::maybe_invoke:
        case Symbol::outer_update: return true;
        default: return false;
    }
}
inline bool optional(Symbol s) {
    if (fixture_only(s)) return true;
    switch (s) {
        case Symbol::jit_mutator_lock: case Symbol::erase_pointer_set:
        case Symbol::update: case Symbol::reinitialize: case Symbol::initialize:
            return true;
        default: return false;
    }
}
}

// Owns all storage referenced by Profile. Do not move it after discover(). This
// read-only stage runs on the host too; JNI probes are a separate final gate.
struct Discovery {
    art_elf::Image elf;
    std::array<Site, static_cast<size_t>(Symbol::Count)> sites{};
    std::vector<uint32_t> patterns;
    Profile profile{};
    std::string error, identity;
    bool fail(const std::string& reason) { error = reason; return false; }
    bool inspect(int api) {
        using namespace discovery_detail;
        if (api < 34 || api > 37) return fail("ART access-flag/GC protocol requires API 34..37");
        sites = {}; patterns.clear(); profile = {}; error.clear();
        for (const auto& c : candidates) {
            auto& site = sites[static_cast<size_t>(c.symbol)];
            if (site.rva) continue;
            bool ambiguous = false;
            const auto* sym = elf.resolve(c.name, &ambiguous);
            if (ambiguous && !fixture_only(c.symbol)) return fail(std::string("ambiguous ART symbol: ") + c.name);
            if (ambiguous) continue; // Test-only operations cannot limit production support.
            if (!sym) continue;
            bool data = data_symbol(c.symbol);
            const auto* bytes = elf.bytes(sym->rva, data ? 8 : 16, !data);
            // Mutable globals may live in .bss; their symbol extent suffices
            // here and the mapped segment is checked again on the device.
            if ((!data && (!bytes || sym->type != 2)) || (data && sym->type != 1))
                return fail(std::string("invalid ART symbol type/range: ") + c.name);
            site.name = c.name; site.rva = sym->rva;
            if (!data) memcpy(site.prologue, bytes, sizeof(site.prologue));
        }
        auto has = [&](Symbol s) { return sites[static_cast<size_t>(s)].rva != 0; };
        for (const auto& c : candidates) if (!has(c.symbol) && !optional(c.symbol))
            return fail(std::string("missing ART symbol: ") + c.name);
        bool zombie = has(Symbol::jit_mutator_lock);
        if (zombie && (!has(Symbol::erase_pointer_set) || !has(Symbol::update) || !has(Symbol::reinitialize)))
            return fail("zombie-code protocol requires erase, UpdateEntryPoints and ReinitializeMethodsCode");
        if (!zombie && (has(Symbol::update) || !has(Symbol::initialize)))
            return fail("locked-code protocol requires InitializeMethodsCode without zombie entry writer");
        profile.family = zombie ? Family::ZombieCode : Family::LockedCode;
        profile.name = zombie ? "arm64-zombie-code-dynamic" : "arm64-locked-code-dynamic";
        identity = elf.id;
        profile.build_id = identity.c_str(); profile.sites = sites.data();
        profile.compilation_kinds[0] = 0;
        profile.compilation_kinds[1] = api >= 37 ? 2 : 1;
        profile.compilation_kinds[2] = api >= 37 ? 3 : 2;

        art_a64::Decoder decoder(elf, profile.site(Symbol::runtime).rva);
        auto probe = [&](const char* name) {
            auto sym = elf.resolve(name); return sym ? decoder.inspect(sym->rva) : art_a64::Facts{};
        };
        auto site_probe = [&](Symbol s) { return decoder.inspect(profile.site(s).rva); };
        auto unique = [](const art_a64::Facts& facts, int root, unsigned width, bool store) -> size_t {
            std::set<size_t> offsets;
            for (const auto& a : facts.accesses) if (a.base.root == root && !a.base.depth &&
                a.width == width && a.store == store && a.offset > 0 && a.offset < 16384)
                offsets.insert(size_t(a.offset));
            return offsets.size() == 1 ? *offsets.begin() : 0;
        };
        auto written = [](const art_a64::Facts& facts, size_t off, size_t size) {
            for (const auto& a : facts.accesses) if (a.base.root == 0 && !a.base.depth && a.store &&
                a.offset >= 0 && size_t(a.offset) <= off && off + size <= size_t(a.offset) + a.width) return true;
            return false;
        };
        auto extent = [](const art_a64::Facts& facts) {
            size_t result = 0;
            for (const auto& a : facts.accesses) if (a.base.root == 0 && !a.base.depth && a.store &&
                a.offset >= 0 && a.offset < 4096) result = std::max(result, size_t(a.offset) + a.width);
            return (result + 7) & ~size_t(7);
        };
        auto& l = profile.layout;
        auto suspend = site_probe(Symbol::suspend), copy = site_probe(Symbol::copy);
        l.runtime_threads = unique(suspend, art_a64::Runtime, 8, false);
        l.runtime_jit = unique(copy, art_a64::Runtime, 8, false);
        l.runtime_linker = unique(probe("_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm"), art_a64::Runtime, 8, false);
        l.runtime_debuggable = unique(probe("_ZN3art7Runtime20SetRuntimeDebugStateENS0_17RuntimeDebugStateE"), 0, 4, true);
        l.runtime_callbacks = unique(probe("_ZN3art7Runtime19GetRuntimeCallbacksEv"), 0, 8, false);
        if (!l.runtime_threads || !l.runtime_jit || !l.runtime_linker || !l.runtime_debuggable || !l.runtime_callbacks)
            return fail("ART Runtime getter/field probe unavailable or ambiguous");
        l.runtime_cache = l.runtime_jit + 8; // Runtime's adjacent Jit / JitCodeCache unique_ptrs.
        auto rt_ctor = probe("_ZN3art7RuntimeC2Ev");
        if (!written(rt_ctor, l.runtime_cache, 8) ||
            !copy.field(art_a64::Runtime, {int64_t(l.runtime_jit)}, 8, 8) ||
            !copy.field(art_a64::Runtime, {int64_t(l.runtime_jit)}, 16, 8) ||
            !probe("_ZN3art3jit3Jit26WaitForCompilationToFinishEPNS_6ThreadE").field(0, {}, 24, 8))
            return fail("ART Jit ownership/options/thread-pool ABI probe failed");

        // Private STL ownership and lock ordering remain explicit ABI rules.
        // These are layout families, not build IDs or function RVAs. Every
        // selected rule must have evidence in the current ELF before use.
        struct Rule { bool zombie; size_t instr, cha, status, saved, zygote, collecting, dead, processed; };
        constexpr Rule rules[] = {
            {true, 0x328,0x248,0x68,0x328,0x3b8,0x410,0x370,0x428},
            {true, 0x330,0x270,0x68,0x340,0x3b8,0x3f0,0x370,0x408},
            {false,0x328,0x208,0x70,0x328,0x370,0x3a8,0,0},
        };
        auto deopt = probe("_ZN3art7Runtime19DeoptimizeBootImageEv");
        auto linker = probe("_ZN3art11ClassLinkerC2EPNS_11InternTableEb");
        auto linker_dtor = probe("_ZN3art11ClassLinkerD2Ev");
        auto status = probe("_ZN3art6mirror5Class15SetStatusLockedENS_11ClassStatusE");
        if (status.addresses.empty()) status = probe("_ZN3art6mirror5Class17SetStatusInternalENS_11ClassStatusE");
        auto saved = probe("_ZN3art3jit12JitCodeCache37GetSavedEntryPointOfPreCompiledMethodEPNS_9ArtMethodE");
        auto collection = site_probe(Symbol::collect_cache), remove = site_probe(Symbol::remove_method_locked);
        const Rule* selected = nullptr;
        for (const auto& rule : rules) {
            if (rule.zombie != zombie || !written(linker, rule.cha, 8) ||
                !linker_dtor.field(0, {}, rule.cha, 8) || !status.address(0, rule.status) ||
                !saved.field(0, {}, rule.saved + 8, 8) || !saved.address(0, rule.zygote) ||
                !collection.field(0, {}, rule.collecting, 1) || !collection.field(0, {}, rule.collecting, 1, true)) continue;
            if (zombie ? !deopt.field(0, {}, rule.instr, 8) : !deopt.address(0, rule.instr)) continue;
            if (zombie && (!collection.field(0, {}, rule.dead, 8) ||
                !remove.address(0, rule.dead) || !collection.address(0, rule.processed))) continue;
            if (selected) return fail("ambiguous ART private-container ABI rules");
            selected = &rule;
        }
        if (!selected) return fail("ART instrumentation/CHA/JIT-cache layout does not match a verified ABI rule");
        l.runtime_instrumentation = selected->instr; l.instrumentation_pointer = zombie;
        l.linker_cha = selected->cha; l.class_status = selected->status;
        l.cache_saved = selected->saved; l.cache_zygote = selected->zygote;
        l.cache_collecting = selected->collecting; l.cache_zombies = selected->dead; l.cache_osr_zombies = selected->processed;
        if (!remove.field(0, {}, 0x310, 8) || !remove.address(0, 0x318))
            return fail("ART code-to-method tree ABI probe failed");
        l.pool_started = unique(site_probe(Symbol::outstanding), 0, 1, false);
        l.pool_waiting = unique(site_probe(Symbol::add_generic_task), 0, 8, false);
        l.pool_threads = l.pool_waiting + 8;
        auto pool = probe("_ZN3art10ThreadPoolD2Ev");
        if (!l.pool_started || !l.pool_waiting || !pool.address(0, 0x20) ||
            !pool.field(0, {}, l.pool_started + 1, 1, true) ||
            !pool.field(0, {}, l.pool_threads, 8) || !pool.field(0, {}, l.pool_threads + 8, 8) ||
            !pool.field(0, {}, l.pool_threads + 16, 8)) return fail("ART compiler thread-pool ABI probe failed");
        l.visitor_size = extent(site_probe(Symbol::visitor_init));
        l.gc_section_size = extent(site_probe(Symbol::gc_enter));
        if (l.visitor_size < 0x100 || l.visitor_size > 0x400 || l.gc_section_size != 24)
            return fail("ART StackVisitor/GC critical-section extent probe failed");

        // Only permanent entry functions of the known SmallPatternMatcher
        // families qualify. A missing/new family remains an unknown entry.
        constexpr const char* prefixes[] = {
            "_ZN3art3jitL11EmptyMethod", "_ZN3art3jitL10ReturnZero", "_ZN3art3jitL9ReturnOne",
            "_ZN3art3jitL20ReturnFirstArgMethod", "_ZN3art3jitL13ReturnFieldAt", "_ZN3art3jitL19ReturnFieldObjectAt",
            "_ZN3art3jitL19ReturnStaticFieldAt", "_ZN3art3jitL25ReturnStaticFieldObjectAt",
            "_ZN3art3jitL10SetFieldAt", "_ZN3art3jitL16SetFieldObjectAt",
            "_ZN3art3jitL16SetStaticFieldAt", "_ZN3art3jitL22SetStaticFieldObjectAt",
            "_ZN3art3jitL21ConstructorSetFieldAt", "_ZN3art3jitL27ConstructorSetFieldObjectAt",
        };
        for (const auto& s : elf.symbols) if (s.type == 2 && s.rva <= UINT32_MAX && elf.bytes(s.rva, 4, true))
            for (const auto* prefix : prefixes) if (s.name.compare(0, strlen(prefix), prefix) == 0) {
                patterns.push_back(uint32_t(s.rva)); break;
            }
        std::sort(patterns.begin(), patterns.end()); patterns.erase(std::unique(patterns.begin(), patterns.end()), patterns.end());
        profile.patterns = patterns.data(); profile.pattern_count = patterns.size();
        return true;
    }
};
}
