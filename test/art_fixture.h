#pragma once
#include "../payload/art_profile.h"
#include <cstdio>
#include <cstdlib>

namespace art_fixture {
using ij2art::art_profile::Symbol;
inline const ij2art::art_profile::Profile& profile(uintptr_t base) {
    const auto* p = ij2art::art_profile::from_base(base);
    if (!p) { fprintf(stderr, "fixture: unsupported libart build\n"); abort(); }
    return *p;
}
template<class Fn> Fn at(uintptr_t base, Symbol symbol) {
    return profile(base).at<Fn>(base, symbol);
}
}
