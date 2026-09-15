#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
. ./sdk.env.sh
. test/lib.sh
CP="$SDK/platforms/android-36/android.jar" LIB="$SDK/platforms/android-36/android.jar" \
    dex_out out/static-original payload/java/org/ij2art/*.java test/java/org/ij2art/StaticOriginal.java
"$NDK_CXX" $(fixture_flags) -Wl,-z,relro,-z,now,-z,noexecstack -o out/static-original.so \
    test/static_original.cpp payload/jni_abi.cpp payload/jni_arm64.S
