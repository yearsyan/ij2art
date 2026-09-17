#!/bin/zsh
set -e
cd "$(dirname "$0")/.."
./build.sh
. ./sdk.env.sh
CXX="$NDK_CXX"
"$CXX" -O2 -Wall -Wextra -Werror -static-libstdc++ -o out/lifecycle-test test/lifecycle.cpp -ldl
(cd cli && cargo build --offline --locked --release --target aarch64-linux-android --example remote-smoke)
cp cli/target/aarch64-linux-android/release/examples/remote-smoke out/remote-smoke
