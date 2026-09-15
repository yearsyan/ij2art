#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
./build.sh
javac --release 8 -Xlint:-options -cp out/ij2art-hook-api.jar -d out/sdk-tests test/java/org/ij2art/BridgeTest.java
java -cp out/ij2art-hook-api.jar:out/sdk-tests org.ij2art.BridgeTest
. ./sdk.env.sh
. test/lib.sh
AJ="$SDK/platforms/android-36/android.jar"
python3 - <<'PY'
from pathlib import Path
p = Path('out/test-padding/fixture/Padding.java')
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text('package fixture; public final class Padding { public static final String DATA = "' + 'multipart-fixture-' * 500 + '"; }\n')
PY
CP="$AJ" LIB="$AJ" dex_out out/test-app test/java/org/ij2art/test/Main.java
CP="$AJ" LIB="$AJ" dex_out out/test-hookapp test/java/org/ij2art/test/HookMain.java \
    test/java/org/ij2art/test/AdmissionMain.java test/java/org/ij2art/test/FixtureMain.java \
    test/java/org/ij2art/test/ConstructorCases.java test/java/org/ij2art/test/SynchronizedCases.java \
    test/java/org/ij2art/test/NativeBindingCases.java test/java/org/ij2art/test/HookUpdateCases.java
CP="out/ij2art-hook-api.jar" LIB="$AJ" D8CP="out/ij2art-hook-api.jar" dex_out out/test-replacement \
    test/java/fixture/Replacement.java test/java/fixture/ConstructorReplacement.java \
    test/java/fixture/SynchronizedReplacement.java test/java/fixture/NativeBindingReplacement.java \
    out/test-padding/fixture/Padding.java
"$NDK_CXX" $(fixture_flags) -o out/art-api-jni.so test/art_jni.cpp payload/art_profile.cpp -ldl
host_test out/dex-store-test test/dex_store.cpp payload/dex_store.cpp
out/dex-store-test out/test-replacement-dex/classes.dex
host_test out/hook-record-test test/hook_record.cpp
out/hook-record-test
host_test out/hook-gate-test test/hook_gate.cpp
out/hook-gate-test
host_test out/hook-versions-test test/hook_versions.cpp
out/hook-versions-test
zsh test/build-update-dex.sh
