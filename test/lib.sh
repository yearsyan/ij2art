# Shared helpers for test/build-*.sh. Source AFTER the script has cd'd to the repo
# root and sourced sdk.env.sh (the helpers read $BUILD_TOOLS); lib.sh verifies both.
[[ -f build.sh ]] || { echo "[!] source test/lib.sh from the repo root" >&2; exit 1; }

# Compile Java sources into <base>-classes, jar to <base>.jar, dex into <base>-dex.
# Optional CP (javac classpath), LIB (d8 --lib) and D8CP (d8 --classpath).
dex_out() {
    local base="$1"; shift
    local -a cp=() lib=() d8cp=()
    [[ -n "${CP:-}" ]] && cp=(-cp "$CP")
    [[ -n "${LIB:-}" ]] && lib=(--lib "$LIB")
    [[ -n "${D8CP:-}" ]] && d8cp=(--classpath "$D8CP")
    rm -rf "$base-classes" "$base-dex"
    mkdir -p "$base-classes" "$base-dex"
    javac --release 8 -Xlint:-options $cp -d "$base-classes" "$@"
    jar cf "$base.jar" -C "$base-classes" .
    "$BUILD_TOOLS/d8" --min-api 31 $lib $d8cp --output "$base-dex" "$base.jar"
}

# Common NDK fixture compile flags; scripts append their own -Wl variants,
# -o, sources and -l libs. Command substitution word-splits the output.
fixture_flags() { print -r -- '-std=c++17 -O2 -fPIC -shared -static-libstdc++ -Wall -Wextra -Werror' }

# Build (not run) a host unit test with the common flag set.
host_test() {
    local out="$1"; shift
    c++ -std=c++17 -O2 -pthread -Wall -Wextra -Werror -o "$out" "$@"
}
