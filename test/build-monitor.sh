#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
. ./sdk.env.sh
mkdir -p out
"$NDK_CLANG" -target bpfel-unknown-none -mcpu=v2 -O2 -nostdinc -Wall -Werror \
    -D__EXPORTED_HEADERS__ -I bpf -I third_party/kernel-uapi/include \
    -c bpf/sys.c -o out/monitor.bpf.o
"$NDK_CLANG" -O2 -Wall -Wextra -Werror test/monitor_fixture.c -o out/monitor-fixture
cargo build --manifest-path cli/Cargo.toml --release --target aarch64-linux-android --offline --locked
# The CLI is rebuilt here on purpose: build.rs embeds out/monitor.bpf.o at compile
# time, so a fresh BPF object only reaches the binary through a rebuild.
cp cli/target/aarch64-linux-android/release/ij2art out/ij2art
cat third_party/libbpf/NOTICE third_party/libbpf/LICENSE.BSD-2-Clause > out/MONITOR_THIRD_PARTY_NOTICES.txt
