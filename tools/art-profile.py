#!/usr/bin/env python3
"""Audit/regenerate ART symbol manifests from ELF64, including .gnu_debugdata.

This does not infer layouts, function signatures or guard coverage. Audit those
separately before adding a build ID to art_profile.cpp. No third-party packages.
"""
import argparse
import json
import lzma
import pathlib
import re
import struct


class Elf:
    def __init__(self, data):
        self.data = data
        if data[:6] != b'\x7fELF\x02\x01' or self.unpack('<H', 18)[0] != 183:
            raise ValueError('expected little-endian arm64 ELF64')
        phoff, shoff = self.unpack('<QQ', 32)
        phsize, phcount, shsize, shcount, names = self.unpack('<HHHHH', 54)
        self.segments = [self.unpack('<IIQQQQQQ', phoff + i * phsize)
                         for i in range(phcount)]
        self.sections = [self.unpack('<IIQQQQIIQQ', shoff + i * shsize)
                         for i in range(shcount)]
        self.names = self.section_data(self.sections[names]) if self.sections else b''

    def unpack(self, fmt, offset):
        return struct.unpack_from(fmt, self.data, offset)

    def section_data(self, section):
        offset, size = section[4:6]
        if offset + size > len(self.data):
            raise ValueError('truncated ELF section')
        return self.data[offset:offset + size]

    @staticmethod
    def string(data, offset):
        return data[offset:data.index(b'\0', offset)].decode()

    def symbols(self):
        result = {}
        for s in self.sections:
            if s[1] in (2, 11):  # SHT_SYMTAB / SHT_DYNSYM
                strings = self.section_data(self.sections[s[6]])
                for pos in range(s[4], s[4] + s[5], s[9]):
                    name, _, _, index, value, _ = self.unpack('<IBBHQQ', pos)
                    if name and index:
                        result[self.string(strings, name)] = value
            elif self.string(self.names, s[0]) == '.gnu_debugdata':
                result.update(Elf(lzma.decompress(self.section_data(s))).symbols())
        return result

    def build_id(self):
        for kind, _, offset, _, _, size, _, _ in self.segments:
            if kind != 4:  # PT_NOTE
                continue
            end = offset + size
            while offset + 12 <= end:
                names, desc, kind = self.unpack('<III', offset)
                name = self.data[offset + 12:offset + 12 + names]
                start = offset + 12 + ((names + 3) & ~3)
                if kind == 3 and name == b'GNU\0':
                    return self.data[start:start + desc].hex()
                offset = start + ((desc + 3) & ~3)
        raise ValueError('ELF has no GNU build ID')

    def prologue(self, address):
        for kind, flags, offset, va, _, size, _, _ in self.segments:
            if kind == 1 and flags & 1 and va <= address and address + 16 <= va + size:
                return self.unpack('<4I', offset + address - va)
        raise ValueError(f'code address {address:#x} is outside executable PT_LOAD')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=pathlib.Path)
    parser.add_argument('--manifest', type=pathlib.Path, required=True)
    parser.add_argument('--build-id', required=True, help='expected exact ELF build ID')
    parser.add_argument('--emit', type=pathlib.Path, help='write refreshed RVAs/prologues instead of checking')
    args = parser.parse_args()
    elf = Elf(args.elf.read_bytes())
    if elf.build_id() != args.build_id:
        raise ValueError(f'build ID mismatch: found {elf.build_id()}')
    symbols = elf.symbols()
    manifest = args.manifest.read_text()
    pattern = re.compile(r'\{"([^"\n]*)", (0x[0-9a-f]+), \{([^}]+)\}\}, // (\w+)')
    count = 0
    errors = []

    def site(match):
        nonlocal count
        name, value, words, key = match.groups()
        expected = tuple(int(word, 16) for word in words.split(','))
        if not int(value, 16):
            return match[0]  # Absent functions require a backend decision, not an inferred substitute.
        count += 1
        address = symbols.get(name)
        # LLVM/LTO suffixes vary across builds; accept only one unambiguous match.
        if address is None and args.emit:
            prefix = re.split(r'\.__uniq|\.llvm', name)[0]
            candidates = [(n, a) for n, a in symbols.items() if re.split(r'\.__uniq|\.llvm', n)[0] == prefix]
            if len(candidates) == 1:
                name, address = candidates[0]
        if address is None:
            errors.append(f'{key}: missing symbol {name}')
            return match[0]
        actual = elf.prologue(address) if any(expected) else (0, 0, 0, 0)
        if not args.emit and (address != int(value, 16) or actual != expected):
            errors.append(f'{key}: symbol RVA/prologue differs ({address:#x})')
        return '{' + json.dumps(name) + f', {address:#x}, {{' + ','.join(hex(x) for x in actual) + '}}, // ' + key

    updated = pattern.sub(site, manifest)
    if not count:
        errors.append('manifest contains no populated sites')
    if errors:
        raise ValueError('\n'.join(errors))
    if args.emit:
        args.emit.write_text(updated)
    print(f'PASS: build {elf.build_id()}, {count} symbol RVAs/prologues, {len(symbols)} ELF symbols')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, IndexError, struct.error, lzma.LZMAError) as error:
        raise SystemExit(str(error)) from None
