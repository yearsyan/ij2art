#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
./build.sh
. ./sdk.env.sh
. test/lib.sh
"$NDK_CXX" $(fixture_flags) -Wl,-z,max-page-size=16384 \
    -o out/inline-fixture.so test/inline_fixture.cpp test/inline_reloc.S test/probe_fixture.S -ldl
"$NDK_CXX" -std=c++17 -O2 -static-libstdc++ -Wall -Wextra -Werror -o out/inline-runner test/inline_runner.cpp -ldl
