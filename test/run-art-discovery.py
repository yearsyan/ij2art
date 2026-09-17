#!/usr/bin/env python3
"""Host regression of the production ELF resolver and ABI probes.

Usage: python3 test/run-art-discovery.py /path/to/device/libart.so --api 37
No ADB, root, or device writes. The source ELF is never modified.
"""
import argparse
import importlib.util
import json
import lzma
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('art_elf_fixture', ROOT / 'tools/art-profile.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def relocate(data, shift):
    """Rebase all ELF virtual addresses without changing PC-relative code."""
    source = module.Elf(data)
    result = bytearray(data)
    phoff, shoff = struct.unpack_from('<QQ', result, 32)
    phsize, phcount, shsize, shcount, _ = struct.unpack_from('<HHHHH', result, 54)
    for i in range(phcount):
        pos = phoff + i * phsize
        for offset in (16, 24):
            value, = struct.unpack_from('<Q', result, pos + offset)
            struct.pack_into('<Q', result, pos + offset, value + shift)
    for i, section in enumerate(source.sections):
        if section[3]:
            struct.pack_into('<Q', result, shoff + i * shsize + 16, section[3] + shift)
        if section[1] in (2, 11):
            for pos in range(section[4], section[4] + section[5], section[9]):
                _, _, _, index, value, _ = struct.unpack_from('<IBBHQQ', result, pos)
                if index and index < 0xff00 and value:
                    struct.pack_into('<Q', result, pos + 8, value + shift)
        if section[1] == 4:
            for pos in range(section[4], section[4] + section[5], section[9]):
                offset, info, addend = struct.unpack_from('<QQq', result, pos)
                struct.pack_into('<Q', result, pos, offset + shift)
                if info & 0xffffffff == 1027 and addend:
                    struct.pack_into('<q', result, pos + 16, addend + shift)
        if source.string(source.names, section[0]) == '.gnu_debugdata':
            # Keep the relocated fixture a valid standalone ELF too. Append a
            # recompressed debug image and update its non-loadable section.
            packed = lzma.compress(relocate(lzma.decompress(source.section_data(section)), shift))
            result.extend(b'\0' * (-len(result) % 8))
            struct.pack_into('<QQ', result, shoff + i * shsize + 24, len(result), len(packed))
            result.extend(packed)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--api', type=int, required=True)
    args = parser.parse_args()
    out = ROOT / 'out/art-dynamic'
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'art-discovery-test'
    subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-O2',
                    str(ROOT / 'test/art_discovery.cpp'), '-o', str(binary)], check=True)
    source = args.elf.read_bytes()
    elf = module.Elf(source)
    debug = next((lzma.decompress(elf.section_data(s)) for s in elf.sections
                  if elf.string(elf.names, s[0]) == '.gnu_debugdata'), b'')
    with tempfile.TemporaryDirectory(prefix='ij2art-discovery-') as folder:
        folder = Path(folder)
        image, mini = folder / 'libart.so', folder / 'libart.debug.so'

        def check(data, failure=None):
            debug_data = debug
            if not failure:
                current = module.Elf(data)
                debug_data = next((lzma.decompress(current.section_data(s)) for s in current.sections
                                   if current.string(current.names, s[0]) == '.gnu_debugdata'), b'')
            image.write_bytes(data)
            mini.write_bytes(debug_data)
            result = subprocess.run([str(binary), str(image), str(mini), str(args.api)],
                                    capture_output=True, text=True, timeout=30)
            if failure:
                assert result.returncode == 1 and failure in result.stderr, result
                return
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout)

        baseline = check(source)
        print('PASS: current ELF; duplicate aliases accepted, ambiguous LTO clones/missing symbols/unknown API rejected')
        changed_id = bytearray(source)
        original = bytes.fromhex(elf.build_id())
        replacement = bytes(x ^ 0xa5 for x in original)
        assert changed_id.count(original) == 1
        changed_id = changed_id.replace(original, replacement)
        other = check(changed_id)
        assert other['id'] == replacement.hex() and other['sites'] == baseline['sites']
        print('PASS: unregistered build ID accepted with unchanged verified ABI')
        shift = 0x4000
        other = check(relocate(changed_id, shift))
        assert other['sites'] == [x + shift if x else 0 for x in baseline['sites']]
        assert other['patterns'] == [x + shift for x in baseline['patterns']]
        print('PASS: every symbol/pattern relocated by 16 KiB; no compiled-in RVAs')
        setter = elf.symbols()['_ZN3art7Runtime20SetRuntimeDebugStateENS0_17RuntimeDebugStateE']
        damaged = bytearray(source)
        segment = next(p for p in elf.segments if p[0] == 1 and p[3] <= setter < p[3] + p[5])
        struct.pack_into('<I', damaged, segment[2] + setter - segment[3], 0xd65f03c0)  # RET before any field access
        check(damaged, failure='Runtime getter/field probe')
        print('PASS: unsupported field access rejected before any runtime mutation')
        check(source[:100], failure='invalid ELF')
        broken = bytearray(source)
        struct.pack_into('<Q', broken, 40, 0xfffffffffffffff0)
        check(broken, failure='invalid ELF')
        print('PASS: truncated/overflowing ELF section tables rejected')
        # Feed short, controlled instructions through the same ELF-backed
        # decoder. Unknown writes and conflicting CFG paths must erase origins.
        method = elf.symbols()['_ZN3art9ArtMethod8CopyFromEPS0_NS_11PointerSizeE']
        segment = next(p for p in elf.segments if p[0] == 1 and p[3] <= method < p[3] + p[5])
        code = segment[2] + method - segment[3]

        def decode(words):
            data = bytearray(source)
            struct.pack_into('<' + 'I' * len(words), data, code, *words)
            image.write_bytes(data)
            mini.write_bytes(debug)
            result = subprocess.run([str(binary), str(image), str(mini), 'decoder'],
                                    capture_output=True, text=True, timeout=30, check=True)
            return json.loads(result.stdout)

        assert decode([0xb9804001, 0xb9004801, 0xd65f03c0]) == [[0, 64, 4, 0], [0, 72, 4, 1]]  # LDRSW / STR
        assert decode([0xaa0003e2, 0xf9402043, 0xd65f03c0]) == [[0, 64, 8, 0]]  # MOV x2,x0 / LDR
        assert decode([0xca000000, 0xf9402001, 0xd65f03c0]) == []  # EOR x0,x0,x0 erases the object origin
        assert decode([0xb4000061, 0xaa0003e2, 0x14000002, 0xaa0103e2, 0xf9402043, 0xd65f03c0]) == []
        print('PASS: signed loads, register renaming, unknown writes and conflicting control-flow origins')
    (out / 'discovery-results.json').write_text(json.dumps({'passed_groups': 6, 'baseline': baseline}, indent=2) + '\n')


if __name__ == '__main__':
    main()
