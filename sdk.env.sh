# Shared toolchain discovery, sourced by the build scripts in the repository root and under
# test/. This file is not a standalone script.
# Machine-specific paths may only come from the calling environment; nothing is hardcoded
# inside the repository:
#   SDK          Android SDK directory   (or ANDROID_HOME / ANDROID_SDK_ROOT)
#   NDK          NDK directory           (or ANDROID_NDK_HOME; defaults to NDK_VERSION, and
#                                        falls back to the highest available version if that
#                                        is missing)
#   BUILD_TOOLS  build-tools directory   (defaults to 36.0.0, and falls back to the highest
#                                        available version if that is missing)
# After the paths are resolved, this exports NDK_CXX / NDK_CLANG and the cargo cross-linker
# environment variables.
if [ -n "${IJ2ART_SDK_ENV_SOURCED:-}" ]; then return 0; fi

if [ -z "${SDK:-}" ]; then
    for _d in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Library/Android/sdk" "$HOME/Android/sdk"; do
        [ -n "$_d" ] && [ -d "$_d" ] && SDK="$_d" && break
    done
fi
[ -n "${SDK:-}" ] && [ -d "$SDK" ] || { echo "[-] Android SDK not found; please set ANDROID_HOME or SDK=<path>" >&2; exit 1; }

NDK_VERSION=28.1.13356709
if [ -z "${NDK:-}" ]; then
    NDK="${ANDROID_NDK_HOME:-}"
    [ -d "$NDK" ] || NDK="$SDK/ndk/$NDK_VERSION"
    [ -d "$NDK" ] || NDK=$(find "$SDK/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)
fi
[ -n "${NDK:-}" ] && [ -d "$NDK" ] || { echo "[-] NDK not found; please set ANDROID_NDK_HOME or NDK=<path>" >&2; exit 1; }

if [ -z "${BUILD_TOOLS:-}" ]; then
    BUILD_TOOLS="$SDK/build-tools/36.0.0"
    [ -d "$BUILD_TOOLS" ] || BUILD_TOOLS=$(find "$SDK/build-tools" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)
fi
[ -n "${BUILD_TOOLS:-}" ] && [ -d "$BUILD_TOOLS" ] || { echo "[-] build-tools not found; please set BUILD_TOOLS=<path>" >&2; exit 1; }

# The prebuilt host directory: first try to match the tag of this machine (including the
# arm64/aarch64 rename), and otherwise fall back to the sole entry that is present.
_NDK_PREBUILT="$NDK/toolchains/llvm/prebuilt"
_HOST_TAG=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
NDK_HOST_TAG=
for _t in "$_HOST_TAG" "${_HOST_TAG/arm64/aarch64}"; do
    [ -d "$_NDK_PREBUILT/$_t" ] && NDK_HOST_TAG="$_t" && break
done
[ -n "$NDK_HOST_TAG" ] || NDK_HOST_TAG=$(ls "$_NDK_PREBUILT" 2>/dev/null | head -1)
[ -n "$NDK_HOST_TAG" ] || { echo "[-] NDK missing toolchains/llvm/prebuilt host directory" >&2; exit 1; }

export NDK_CXX="$_NDK_PREBUILT/$NDK_HOST_TAG/bin/aarch64-linux-android31-clang++"
export NDK_CLANG="$_NDK_PREBUILT/$NDK_HOST_TAG/bin/aarch64-linux-android31-clang"
[ -x "$NDK_CXX" ] || { echo "[-] missing cross compiler: $NDK_CXX" >&2; exit 1; }
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_CLANG"
export CC_aarch64_linux_android="$NDK_CLANG"
export AR_aarch64_linux_android="$_NDK_PREBUILT/$NDK_HOST_TAG/bin/llvm-ar"
IJ2ART_SDK_ENV_SOURCED=1
