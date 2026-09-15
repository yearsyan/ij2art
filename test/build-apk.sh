#!/bin/zsh
# Build the real-App verification APK (unsigned) + its replacement dex.
# Run ./build.sh first so out/payload.so and out/ij2art-hook-api.jar exist.
#
# Finish + install (OPPO/OnePlus USB-install prompt is bypassed with root):
#   app-signer sign out/apktest-aligned.apk --credential "<Android APK cred>"
#   adb push out/apktest-aligned-signed.apk /data/local/tmp/apktest.apk
#   adb shell su -c "pm install -r /data/local/tmp/apktest.apk"
# Phase A (self-load): adb shell su -c "touch /data/local/tmp/ij2art-apktest-selfload"
# then launch; workers log HOT/REF/GRT/INS probes under tag ij2art.apktest.
set -e
cd "$(dirname "$0")/.."
. ./sdk.env.sh
. test/lib.sh
BT="$BUILD_TOOLS"
AJ="$SDK/platforms/android-36/android.jar"
CXX="$NDK_CXX"
PREFIX=""
if [[ "${1:-}" == "--aot" ]]; then PREFIX="aot-"; fi
WORK="out/${PREFIX}apk"
MANIFEST="test/apk/AndroidManifest.xml"
if [[ -n "$PREFIX" ]]; then
    MANIFEST="out/aot-AndroidManifest.xml"
    sed -e 's/package="org.ij2art.apktest"/package="org.ij2art.aottest"/' \
        -e 's/android:name=".MainActivity"/android:name="org.ij2art.apktest.MainActivity"/' \
        test/apk/AndroidManifest.xml > "$MANIFEST"
fi

for f in out/payload.so out/ij2art-hook-api.jar; do
    [ -f "$f" ] || { echo "missing $f (run ./build.sh)"; exit 1; }
done
rm -rf "$WORK-zip"
mkdir -p "$WORK-zip/lib/arm64-v8a"

echo "[*] app dex"
CP="$AJ" LIB="$AJ" dex_out "$WORK-app" test/apk/java/org/ij2art/apktest/MainActivity.java \
    test/java/org/ij2art/test/ConstructorCases.java test/java/org/ij2art/test/SynchronizedCases.java \
    test/java/org/ij2art/test/NativeBindingCases.java test/java/org/ij2art/test/HookUpdateCases.java \
    test/java/org/ij2art/test/JavaCallCases.java

echo "[*] replacement dex"
CP="out/ij2art-hook-api.jar" LIB="$AJ" D8CP="out/ij2art-hook-api.jar" dex_out "$WORK-repl" \
    test/apk/java/fixture/ReplacementApk.java test/java/fixture/ConstructorReplacement.java \
    test/java/fixture/SynchronizedReplacement.java test/java/fixture/NativeBindingReplacement.java
mv "$WORK-repl-dex/classes.dex" "$WORK-replacement.dex"

echo "[*] native libs"
"$CXX" $(fixture_flags) \
    -o "$WORK-zip/lib/arm64-v8a/libapkbridge.so" test/apk/jni/apkbridge.cpp payload/art_profile.cpp -ldl -llog
cp out/payload.so "$WORK-zip/lib/arm64-v8a/libpayload.so"

echo "[*] package"
"$BT/aapt2" link -o "${WORK}test-unsigned.apk" --manifest "$MANIFEST" \
    -I "$AJ" --min-sdk-version 31 --target-sdk-version 36
cp "$WORK-app-dex/classes.dex" "$WORK-zip/classes.dex"
(cd "$WORK-zip" && zip -q -r "../${PREFIX}apktest-unsigned.apk" classes.dex lib)
"$BT/zipalign" -f 4 "${WORK}test-unsigned.apk" "${WORK}test-aligned.apk"
echo "[+] ${WORK}test-aligned.apk, $WORK-replacement.dex"
