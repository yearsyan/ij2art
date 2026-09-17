#!/bin/zsh
# ij2art build: payload.so and carrier.so (built with the NDK), plus the CLI (built with cargo).
# Toolchain discovery is described in sdk.env.sh; the paths can be overridden with the
# SDK/NDK/BUILD_TOOLS or ANDROID_* environment variables.
set -e
cd "$(dirname "$0")"
. ./sdk.env.sh
CXX="$NDK_CXX"
LLD="$(dirname "$NDK_CXX")/ld.lld"

mkdir -p out
echo "[*] Hook SDK (Java API + embedded dex)"
mkdir -p out/sdk-classes out/sdk-dex
javac --release 8 -Xlint:-options -cp "$SDK/platforms/android-36/android.jar" \
    -d out/sdk-classes payload/java/org/ij2art/*.java
jar cf out/ij2art-hook-api.jar -C out/sdk-classes .
"$BUILD_TOOLS/d8" --min-api 31 --lib "$SDK/platforms/android-36/android.jar" --output out/sdk-dex out/ij2art-hook-api.jar
python3 - <<'PY'
from pathlib import Path
b = Path('out/sdk-dex/classes.dex').read_bytes()
rows = [','.join(str(v) for v in b[n:n+24]) for n in range(0, len(b), 24)]
Path('out/hook_sdk.h').write_text('#pragma once\nstatic const unsigned char ij2art_hook_sdk[] = {\n' + ',\n'.join(rows) + '\n};\n')
PY
echo "[*] payload.so"
zsh third_party/shadowhook/build.sh
"$CXX" -std=c++17 -O2 -fPIC -shared -static-libstdc++ -Wl,--build-id=sha1 -fvisibility=hidden \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--exclude-libs,ALL \
    -Wl,-z,max-page-size=16384 -Wl,--no-undefined -I out -o out/payload.so \
    payload/payload.cpp payload/ring.cpp payload/art.cpp payload/dex_store.cpp payload/java_calls.cpp \
    payload/replace.cpp payload/jni_abi.cpp payload/jni_arm64.S payload/inline_hook.cpp payload/loader.cpp payload/art_entry_guard.cpp payload/art_backend.cpp payload/art_profile.cpp \
    out/shadowhook/libshadowhook.a -llog -ldl

echo "[*] carrier.so (with payload.so embedded)"
# The payload bytes are packed into a linkable object whose symbols are
# _binary_payload_so_start and _binary_payload_so_end.
(cd out && "$LLD" -m aarch64linux -r -b binary payload.so -o payload_blob.o)
# The trampoline stub is assembled on its own because bti/xpacib need a higher -march; on
# older cores these instructions live in hint space and execute as NOPs, so this does not
# restrict the armv8-a baseline chosen for the rest of carrier.
"$NDK_CLANG" -march=armv8.5-a -c carrier/teardown_stub.S -o out/teardown_stub.o
"$CXX" -O2 -fPIC -shared -static-libstdc++ -Wl,--build-id=sha1 -fvisibility=hidden -ffunction-sections -fdata-sections \
    -I out \
    -Wl,--gc-sections -o out/carrier.so carrier/carrier.cpp out/teardown_stub.o out/payload_blob.o -ldl -llog

echo "[*] monitor.bpf.o (eBPF)"
# -nostdinc: use only the kernel uapi vendored in this repository, with no BTF and no global
# data section (see docs/ebpf-monitor.md, D3/D4).
"$NDK_CLANG" -target bpfel-unknown-none -mcpu=v2 -O2 -nostdinc -Wall -Werror \
    -D__EXPORTED_HEADERS__ -I bpf -I third_party/kernel-uapi/include \
    -c bpf/sys.c -o out/monitor.bpf.o

echo "[*] ij2art (CLI)"
(cd cli && cargo build --release --target aarch64-linux-android --quiet)
cp cli/target/aarch64-linux-android/release/ij2art out/
cat third_party/libbpf/NOTICE third_party/libbpf/LICENSE.BSD-2-Clause >> out/THIRD_PARTY_NOTICES.txt

echo "[+] done: out/{ij2art, carrier.so, payload.so, monitor.bpf.o}"
