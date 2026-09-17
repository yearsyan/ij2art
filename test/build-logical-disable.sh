#!/bin/zsh
# hook-gate-test lives in build-art-api.sh; this script only builds the device fixture.
set -e
cd "$(dirname "$0")/.."
. ./sdk.env.sh
. test/lib.sh
CP="$SDK/platforms/android-36/android.jar" LIB="$SDK/platforms/android-36/android.jar" \
    dex_out out/logical-disable payload/java/org/ij2art/*.java test/java/org/ij2art/LogicalDisable.java
"$NDK_CXX" $(fixture_flags) -Wl,-z,relro,-z,now,-z,noexecstack -o out/logical-disable.so \
    test/logical_disable.cpp payload/dex_store.cpp payload/jni_abi.cpp payload/jni_arm64.S payload/art_profile.cpp out/shadowhook/libshadowhook.a -llog -ldl
