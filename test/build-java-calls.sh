#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
. ./sdk.env.sh
. test/lib.sh
AJ="$SDK/platforms/android-36/android.jar"
# art-api-jni.so is owned by build-art-api.sh; this script only consumes it.
[[ -f out/art-api-jni.so ]] || { echo "missing out/art-api-jni.so (run test/build-art-api.sh)" >&2; exit 1; }
CP="$AJ" LIB="$AJ" dex_out out/java-call-app test/java/org/ij2art/test/JavaCallMain.java test/java/org/ij2art/test/JavaCallCases.java
CP="$AJ" LIB="$AJ" dex_out out/java-call-helper test/java-call-dex/fixture/JavaCallHelper.java
