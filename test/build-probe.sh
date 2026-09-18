#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
mkdir -p out
c++ -std=c++17 -O2 -pthread -Wall -Wextra -Werror test/probe_buffer.cpp -o out/probe-buffer-test
out/probe-buffer-test
zsh test/build-inline.sh
