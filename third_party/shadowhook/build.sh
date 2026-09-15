#!/bin/zsh
# Called from the project root after sourcing sdk.env.sh.
set -e
root=third_party/shadowhook
mkdir -p out/shadowhook
objects=()
while IFS= read -r src; do
    obj="out/shadowhook/${src//\//_}.o"
    "$NDK_CLANG" -std=c11 -Os -fPIC -fvisibility=hidden -ffunction-sections -fdata-sections \
        -DIJ2ART_SHADOWHOOK_ADDRESS_ONLY -Wall -Wextra -Werror \
        -I "$root" -I "$root/include" -I "$root/common" -I "$root/arch/arm64" \
        -I "$root/third_party/bsd" -I "$root/third_party/lss" -I "$root/third_party/xdl" \
        -c "$root/$src" -o "$obj"
    objects+=("$obj")
done < "$root/sources.txt"
rm -f out/shadowhook/libshadowhook.a
"$(dirname "$NDK_CLANG")/llvm-ar" rcs out/shadowhook/libshadowhook.a "${objects[@]}"
python3 - <<'PY'
from pathlib import Path
root = Path('third_party/shadowhook')
notices = ['ShadowHook v2.0.1 (854c775c2c3676e57a0f383597ebf420b5204161) and native dependencies\n']
for name in ['LICENSE', 'third_party/xdl/LICENSE', 'third_party/lss/LICENSE',
             'third_party/bsd/queue.h', 'third_party/bsd/tree.h',
             'third_party/xdl/xdl_lzma.c', 'third_party/lss/linux_syscall_support_android_ext.h']:
    text = (root / name).read_text()
    if name.endswith('.h') and text.startswith('/*'):
        text = text[:text.index('*/') + 2]
    elif name.endswith(('.h', '.c')):
        text = text[:text.index('// Created by')]
    notices.append('\n--- ' + name + ' ---\n' + text)
Path('out/THIRD_PARTY_NOTICES.txt').write_text('\n'.join(notices))
PY
