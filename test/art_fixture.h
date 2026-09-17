#pragma once
#include "../payload/art_profile.h"
#include <cstdio>
#include <cstdlib>

namespace art_fixture {
using ij2art::art_profile::Symbol;
inline const ij2art::art_profile::Profile& profile(uintptr_t base) {
    char error[512]{};
    const auto* p = ij2art::art_profile::discover(base, error, sizeof(error));
    if (!p) { fprintf(stderr, "fixture: ART compatibility discovery failed: %s\n", error); abort(); }
    return *p;
}
template<class Fn> Fn at(uintptr_t base, Symbol symbol) {
    return profile(base).at<Fn>(base, symbol);
}

// Some ART builds inline the public STL wrappers and CHA::AddDependency. Use
// their exact outlined allocator-owning helpers, not NDK STL over ART storage.
// LLVM 22's lambda holds the container pointer; older member helpers take the
// container directly. A returned iterator/bool pair occupies x0/x1 on arm64.
struct InsertResult { void* node; uintptr_t inserted; };
inline void* helper_receiver(uintptr_t base, Symbol symbol, void*& container) {
    return !strncmp(profile(base).site(symbol).name, "_ZZ", 3) ? &container : container;
}
inline void insert_code(uintptr_t base, void* set, const void* code) {
    if (auto insert = at<void(*)(void*, const void*)>(base, Symbol::insert_pointer_set)) {
        insert(set, &code);
    } else {
        at<InsertResult(*)(void*, const void*, const void*)>(base, Symbol::emplace_pointer_set)(
            helper_receiver(base, Symbol::emplace_pointer_set, set), &code, &code);
    }
}
inline void add_dependency(uintptr_t base, void* cha, void* method, const void* header) {
    if (auto add = at<void(*)(void*, void*, void*, const void*)>(base, Symbol::add_dependency)) {
        add(cha, method, method, header);
    } else {
        // An empty vector in the temporary map value is moved by ART's helper.
        struct { void* key; void* begin; void* end; void* capacity; } value{method, nullptr, nullptr, nullptr};
        auto inserted = at<InsertResult(*)(void*, const void*, void*)>(base, Symbol::emplace_dependency)(
            helper_receiver(base, Symbol::emplace_dependency, cha), &value.key, &value);
        struct { void* method; const void* header; } pair{method, header};
        at<void*(*)(void*, void*)>(base, Symbol::append_dependency)(
            static_cast<unsigned char*>(inserted.node) + 0x18, &pair);
    }
}
}
