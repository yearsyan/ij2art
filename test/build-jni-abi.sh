#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
. ./sdk.env.sh
. test/lib.sh
dex_out out/jni-abi test/java/org/ij2art/test/JniAbi.java
"$NDK_CXX" $(fixture_flags) -Wl,-z,relro,-z,now,-z,noexecstack \
    -o out/jni-abi.so test/jni_abi.cpp payload/jni_abi.cpp payload/jni_arm64.S
