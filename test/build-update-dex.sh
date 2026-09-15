#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
. ./sdk.env.sh
. test/lib.sh
for version in a b; do
    CP="out/ij2art-hook-api.jar" LIB="$SDK/platforms/android-36/android.jar" \
        D8CP="out/ij2art-hook-api.jar" dex_out "out/update-$version" test/update-$version/fixture/*.java
done
