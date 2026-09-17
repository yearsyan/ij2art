// Minimal ELF64 parsing: it looks up the virtual address of a dynsym symbol and the GOT
// relocation offsets.
// There are two parsing paths. A) Section headers -- system libraries usually keep them,
// and this is the fastest path. B) The program header fallback, that is, PT_DYNAMIC plus
// the DT_* tags -- this still works when the section headers have been stripped (by
// llvm-objcopy --strip-sections or a vendor packer), because the program header is
// metadata required for dynamic loading and is therefore never removed.
// MemElf runs the very same dynamic-segment parsing over the memory of a remote process,
// so it does not depend on a library file on disk at all.
use std::path::Path;

use crate::procfs;

macro_rules! get {
    ($b:expr, $off:expr, $t:ty) => {{
        let o = $off as usize;
        if o + core::mem::size_of::<$t>() > $b.len() {
            return None;
        }
        unsafe { core::ptr::read_unaligned($b.as_ptr().add(o) as *const $t) }
    }};
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn read_elf(path: &Path) -> Option<Vec<u8>> {
    let b = std::fs::read(path).ok()?;
    elf64(&b)?;
    Some(b)
}

fn elf64(b: &[u8]) -> Option<()> {
    (b.len() >= 64 && &b[0..4] == b"\x7fELF" && b[4] == 2 && b[5] == 1).then_some(())
}

// ---------------- A) section-header path (the original implementation) ----------------
// A return value of None means a structural parse failure (there are no section headers,
// or there is no dynsym section), which is distinct from "the symbol does not exist".

fn sections_sym_vaddr(b: &[u8], name: &str) -> Option<u64> {
    // e_shoff@0x28 u64, e_shentsize@0x3A u16, e_shnum@0x3C u16
    let shoff = get!(b, 0x28, u64);
    let shentsize = get!(b, 0x3A, u16) as u64;
    let shnum = get!(b, 0x3C, u16) as u64;
    if shoff == 0 || shnum == 0 {
        return None;
    }
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let sh_type = get!(b, sh + 4, u32);
        // Both SHT_DYNSYM(11) and SHT_SYMTAB(2) are checked: libart's art_quick_* and
        // most of its internal symbols are LOCAL HIDDEN and exist only in .symtab, so when
        // the symbol is not found in dynsym we keep scanning symtab.
        if sh_type != 11 && sh_type != 2 {
            continue;
        }
        let link = get!(b, sh + 40, u32); // sh_link -> the associated string table section
        let sym_off = get!(b, sh + 24, u64);
        let sym_size = get!(b, sh + 32, u64);
        let strsh = shoff + link as u64 * shentsize;
        let str_off = get!(b, strsh + 24, u64);
        for j in 0..(sym_size / 24) {
            let s = sym_off + j * 24;
            let st_name = get!(b, s, u32) as u64;
            let st_value = get!(b, s + 8, u64);
            if get!(b, s + 6, u16) == 0 {
                continue;
            } // SHN_UNDEF is not a definition
            if cstr_at(b, str_off + st_name) == Some(name.as_bytes()) {
                return Some(st_value);
            }
        }
    }
    None
}

fn sections_got_offsets(b: &[u8], name: &str) -> Option<Vec<u64>> {
    let shoff = get!(b, 0x28, u64);
    let shentsize = get!(b, 0x3A, u16) as u64;
    let shnum = get!(b, 0x3C, u16) as u64;
    if shoff == 0 || shnum == 0 {
        return None;
    }

    let mut dynsym: Option<(u64, u64)> = None; // (sym_off, str_off)
    let mut relas: Vec<u64> = Vec::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let sh_type = get!(b, sh + 4, u32);
        if sh_type == 11 {
            let link = get!(b, sh + 40, u32) as u64;
            let strsh = shoff + link * shentsize;
            dynsym = Some((get!(b, sh + 24, u64), get!(b, strsh + 24, u64)));
        } else if sh_type == 4 {
            relas.push(sh); // SHT_RELA
        }
    }
    let (sym_off, str_off) = dynsym?;
    let mut out = Vec::new();
    for sh in relas {
        let off = get!(b, sh + 24, u64);
        let size = get!(b, sh + 32, u64);
        for j in 0..(size / 24) {
            let r = off + j * 24;
            let r_offset = get!(b, r, u64);
            let r_info = get!(b, r + 8, u64);
            let sym_idx = (r_info >> 32) as u64;
            let st_name = get!(b, sym_off + sym_idx * 24, u32) as u64;
            if cstr_at(b, str_off + st_name) == Some(name.as_bytes()) {
                out.push(r_offset);
            }
        }
    }
    Some(out)
}

fn cstr_at(b: &[u8], off: u64) -> Option<&[u8]> {
    let start = off as usize;
    if start >= b.len() {
        return None;
    }
    let end = b[start..].iter().position(|&c| c == 0).map(|p| start + p)?;
    Some(&b[start..end])
}

// ---------------- B) program header + dynamic segment path ----------------
// (used as the file fallback and shared with the remote-memory parser)

/// An abstract reader, so that a file (where a vaddr is translated into a file offset via
/// PT_LOAD) and remote memory (where runtime absolute addresses are used) can share the
/// same dynamic-segment parsing logic.
trait VaReader {
    fn vread(&mut self, addr: u64, len: usize) -> Option<Vec<u8>>;
    /// Translate a link-time vaddr into this reader's address space (for a file the value
    /// is used as-is; for memory +load_bias is added).
    fn adjust(&self, link_vaddr: u64) -> u64;
}

struct FileReader<'a> {
    b: &'a [u8],
    loads: Vec<(u64, u64, u64)>, // (p_offset, p_vaddr, p_filesz)
}
impl VaReader for FileReader<'_> {
    fn vread(&mut self, addr: u64, len: usize) -> Option<Vec<u8>> {
        for &(off, pva, fsz) in &self.loads {
            if addr >= pva && addr + len as u64 <= pva + fsz {
                let s = (off + addr - pva) as usize;
                return self.b.get(s..s + len).map(|x| x.to_vec());
            }
        }
        None
    }
    fn adjust(&self, v: u64) -> u64 {
        v
    }
}

struct MemReader {
    pid: i32,
    bias: u64,
}
impl VaReader for MemReader {
    fn vread(&mut self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut v = vec![0u8; len];
        if procfs::vm_read(self.pid, addr, &mut v) {
            Some(v)
        } else {
            None
        }
    }
    // bionic does not rewrite the d_ptr entries of the dynamic segment (it keeps the
    // link-time vaddr). Should we meet an implementation that does rewrite them, the value
    // must land inside [bias, bias+4G), so both conventions are handled.
    fn adjust(&self, v: u64) -> u64 {
        if self.bias != 0 && v >= self.bias && v < self.bias + (1 << 32) {
            v
        } else {
            self.bias + v
        }
    }
}

struct DynTags {
    strtab: u64,
    strsz: u64,
    symtab: u64,
    hash: u64,
    gnu_hash: u64,
    rela: Option<(u64, u64)>, // (table address, byte count)
    jmprel: Option<(u64, u64)>,
}

fn read_dyn_tags(r: &mut dyn VaReader, dyn_addr: u64) -> Option<DynTags> {
    // Read entry by entry (16 bytes each): .dynamic often sits right at the end of the
    // PT_LOAD segment that contains it, so reading it as a single block would run past the
    // segment and fail.
    let mut t = DynTags {
        strtab: 0,
        strsz: 0,
        symtab: 0,
        hash: 0,
        gnu_hash: 0,
        rela: None,
        jmprel: None,
    };
    let (mut relasz, mut pltrelsz, mut rela_a, mut jmprel_a) = (0u64, 0u64, 0u64, 0u64);
    for i in 0..128 {
        let e = r.vread(dyn_addr + i * 16, 16)?;
        match rd64(&e, 0) as i64 {
            0 => break,                             // DT_NULL
            2 => pltrelsz = rd64(&e, 8),            // DT_PLTRELSZ
            4 => t.hash = rd64(&e, 8),              // DT_HASH
            5 => t.strtab = rd64(&e, 8),            // DT_STRTAB
            6 => t.symtab = rd64(&e, 8),            // DT_SYMTAB
            7 => rela_a = rd64(&e, 8),              // DT_RELA
            8 => relasz = rd64(&e, 8),              // DT_RELASZ
            10 => t.strsz = rd64(&e, 8),            // DT_STRSZ
            23 => jmprel_a = rd64(&e, 8),           // DT_JMPREL
            0x6ffffef5 => t.gnu_hash = rd64(&e, 8), // DT_GNU_HASH
            _ => {}
        }
    }
    if t.strtab == 0 || t.symtab == 0 {
        return None;
    }
    if rela_a != 0 {
        t.rela = Some((rela_a, relasz));
    }
    if jmprel_a != 0 {
        t.jmprel = Some((jmprel_a, pltrelsz));
    }
    // Normalize every d_ptr into the reader's address space
    t.strtab = r.adjust(t.strtab);
    t.symtab = r.adjust(t.symtab);
    t.hash = if t.hash != 0 { r.adjust(t.hash) } else { 0 };
    t.gnu_hash = if t.gnu_hash != 0 {
        r.adjust(t.gnu_hash)
    } else {
        0
    };
    t.rela = t.rela.map(|(a, s)| (r.adjust(a), s));
    t.jmprel = t.jmprel.map(|(a, s)| (r.adjust(a), s));
    Some(t)
}

/// The number of dynsym entries. DT_SYMTAB carries no size tag, so we try, in order,
/// DT_HASH.nchain, then the end of the GnuHash chain, and finally the dynstr adjacency as
/// a backstop.
fn dynsym_count(r: &mut dyn VaReader, t: &DynTags) -> Option<usize> {
    if t.hash != 0 {
        if let Some(h) = r.vread(t.hash, 8) {
            return Some(rd32(&h, 4) as usize); // nchain == the number of dynsym entries
        }
    }
    if t.gnu_hash != 0 {
        if let Some(hd) = r.vread(t.gnu_hash, 16) {
            let nbuckets = rd32(&hd, 0) as usize;
            let symndx = rd32(&hd, 4) as usize;
            let bloom = rd32(&hd, 8) as usize;
            if nbuckets < 0x100000 && bloom < 0x10000 {
                let buckets_addr = t.gnu_hash + 16 + bloom as u64 * 8;
                let mut maxb = symndx.saturating_sub(1); // 0..symndx-1 always exists
                if nbuckets > 0 {
                    if let Some(bs) = r.vread(buckets_addr, nbuckets * 4) {
                        for i in 0..nbuckets {
                            maxb = maxb.max(rd32(&bs, i * 4) as usize);
                        }
                    }
                }
                let chain_addr = buckets_addr + nbuckets as u64 * 4;
                let mut i = maxb;
                while i >= symndx && i < 0x100000 {
                    // A chain entry corresponds to symbol (symndx + k); the lowest bit set
                    // to 1 marks the end of the chain.
                    let Some(c) = r.vread(chain_addr + (i - symndx) as u64 * 4, 4) else {
                        break;
                    };
                    if c[0] & 1 == 1 {
                        break;
                    }
                    i += 1;
                }
                return Some((i + 1).min(0x100000));
            }
        }
    }
    // Backstop heuristic: in the lld layout, dynsym sits immediately before dynstr
    if t.strtab > t.symtab {
        return Some(((t.strtab - t.symtab) / 24) as usize);
    }
    None
}

fn name_eq(strs: &[u8], off: usize, name: &[u8]) -> bool {
    off + name.len() < strs.len()
        && &strs[off..off + name.len()] == name
        && strs[off + name.len()] == 0
}

fn load_dynsym(r: &mut dyn VaReader, t: &DynTags, count: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let syms = r.vread(t.symtab, count.min(200_000) * 24)?;
    let slen = if t.strsz != 0 {
        (t.strsz as usize).min(4 << 20)
    } else {
        1 << 20
    };
    let strs = r
        .vread(t.strtab, slen)
        .or_else(|| r.vread(t.strtab, 64 << 10))?;
    Some((syms, strs))
}

fn find_sym(syms: &[u8], strs: &[u8], name: &str) -> Option<u64> {
    for j in 0..syms.len() / 24 {
        let noff = rd32(syms, j * 24) as usize;
        if rd16(syms, j * 24 + 6) == 0 {
            continue;
        }
        if name_eq(strs, noff, name.as_bytes()) {
            return Some(rd64(syms, j * 24 + 8));
        }
    }
    None
}

/// Scan the relocation tables and return the slot addresses of the matching symbol. The
/// addresses have already gone through reader.adjust, so each one is in its own address
/// space.
fn rela_slots(
    r: &mut dyn VaReader,
    t: &DynTags,
    syms: &[u8],
    strs: &[u8],
    name: &str,
) -> Option<Vec<u64>> {
    let mut tables: Vec<(u64, u64)> = Vec::new();
    if let Some(j) = t.jmprel {
        tables.push(j);
    }
    if let Some(a) = t.rela {
        // In some layouts JMPREL is nested inside RELA, so the duplicate is removed.
        if let Some(&(ja, js)) = tables.first() {
            if ja >= a.0 && ja + js <= a.0 + a.1 {
                tables.clear();
            }
        }
        tables.push(a);
    }
    let mut out = Vec::new();
    for (addr, size) in tables {
        if size == 0 {
            continue;
        }
        let tbl = r.vread(addr, (size as usize).min(4 << 20))?;
        for e in tbl.chunks_exact(24) {
            let idx = (rd64(e, 8) >> 32) as usize; // r_info's high 32 bits hold the symbol index
            if idx == 0 || idx * 24 + 4 > syms.len() {
                continue;
            }
            if name_eq(strs, rd32(syms, idx * 24) as usize, name.as_bytes()) {
                out.push(r.adjust(rd64(e, 0)));
            }
        }
    }
    Some(out)
}

// ---------------- file entry (section headers first, PHDR as fallback) ----------------

fn phdr_layout(b: &[u8]) -> Option<(Vec<(u64, u64, u64)>, u64)> {
    let phoff = get!(b, 0x20, u64);
    let phent = get!(b, 0x36, u16) as u64;
    let phnum = get!(b, 0x38, u16) as u64;
    if phnum == 0 || phnum > 128 || phent < 56 {
        return None;
    }
    let mut loads = Vec::new();
    let mut dyn_va = 0u64;
    for i in 0..phnum {
        let ph = phoff + i * phent;
        match get!(b, ph, u32) {
            1 => loads.push((
                get!(b, ph + 8, u64),
                get!(b, ph + 16, u64),
                get!(b, ph + 32, u64),
            )), // PT_LOAD
            2 => dyn_va = get!(b, ph + 16, u64), // PT_DYNAMIC
            _ => {}
        }
    }
    if dyn_va == 0 || loads.is_empty() {
        return None;
    }
    Some((loads, dyn_va))
}

fn with_phdr<T>(
    b: &[u8],
    f: impl FnOnce(&mut FileReader, DynTags, usize) -> Option<T>,
) -> Option<T> {
    let (loads, dyn_va) = phdr_layout(b)?;
    let mut r = FileReader { b, loads };
    let t = read_dyn_tags(&mut r, dyn_va)?;
    let n = dynsym_count(&mut r, &t)?;
    f(&mut r, t, n)
}

pub fn sym_vaddr(path: &Path, name: &str) -> Option<u64> {
    let b = read_elf(path)?;
    sym_vaddr_bytes(&b, name)
}

pub fn sym_vaddr_bytes(b: &[u8], name: &str) -> Option<u64> {
    elf64(b)?;
    sections_sym_vaddr(b, name).or_else(|| {
        with_phdr(b, |r, t, n| {
            let (syms, strs) = load_dynsym(r, &t, n)?;
            find_sym(&syms, &strs, name)
        })
    })
}

/// A return value of None means a structural parse failure (the file cannot be read, the
/// ELF is invalid, or the dynamic segment is missing). That is distinct from "the symbol
/// was not imported" (which is Some with an empty vector), and it lets the caller decide
/// whether to fall back to parsing the remote memory.
pub fn got_reloc_offsets_checked(path: &Path, name: &str) -> Option<Vec<u64>> {
    let b = read_elf(path)?;
    sections_got_offsets(&b, name).or_else(|| {
        with_phdr(&b, |r, t, n| {
            let (syms, strs) = load_dynsym(r, &t, n)?;
            rela_slots(r, &t, &syms, &strs, name)
        })
    })
}

// ---------------- parsing remote process memory (MemElf) ----------------
// This parses the library inside the target process's memory directly through PT_DYNAMIC,
// without depending on a file on disk. That avoids a missing file, a file that has been
// stripped, and version drift from the loaded copy. All returned values are **runtime
// absolute addresses**.

pub struct MemElf {
    reader: MemReader,
    tags: DynTags,
    count: usize,
    cache: Option<(Vec<u8>, Vec<u8>)>, // (dynsym, dynstr), loaded lazily
}

impl MemElf {
    /// base = the library's load base, that is, the start of the off==0 r--p segment in maps
    pub fn load(pid: i32, base: u64) -> Option<MemElf> {
        let mut eh = [0u8; 64];
        if !procfs::vm_read(pid, base, &mut eh) {
            return None;
        }
        if &eh[0..4] != b"\x7fELF" || eh[4] != 2 {
            return None;
        }
        let phoff = rd64(&eh, 0x20);
        let phent = rd16(&eh, 0x36) as u64;
        let phnum = rd16(&eh, 0x38) as u64;
        if phnum == 0 || phnum > 128 || phent < 56 {
            return None;
        }
        let mut ph = vec![0u8; phent as usize * phnum as usize];
        if !procfs::vm_read(pid, base + phoff, &mut ph) {
            return None;
        }
        let (mut load0, mut have_load0, mut dyn_va) = (0u64, false, 0u64);
        for i in 0..phnum as usize {
            let o = i * phent as usize;
            match rd32(&ph, o) {
                1 if !have_load0 => {
                    load0 = rd64(&ph, o + 16);
                    have_load0 = true;
                }
                2 => dyn_va = rd64(&ph, o + 16),
                _ => {}
            }
        }
        if !have_load0 || dyn_va == 0 {
            return None;
        }
        let bias = base.wrapping_sub(load0); // normal lib: PT_LOAD[0].p_vaddr == 0, bias == base
        let mut reader = MemReader { pid, bias };
        let tags = read_dyn_tags(&mut reader, bias + dyn_va)?;
        let count = dynsym_count(&mut reader, &tags)?;
        Some(MemElf {
            reader,
            tags,
            count,
            cache: None,
        })
    }

    fn ensure(&mut self) -> bool {
        if self.cache.is_none() {
            let mut r = MemReader {
                pid: self.reader.pid,
                bias: self.reader.bias,
            };
            self.cache = load_dynsym(&mut r, &self.tags, self.count);
        }
        self.cache.is_some()
    }

    /// The symbol's runtime absolute address
    pub fn sym_addr(&mut self, name: &str) -> Option<u64> {
        if !self.ensure() {
            return None;
        }
        let v = {
            let (syms, strs) = self.cache.as_ref()?;
            find_sym(syms, strs, name)?
        };
        Some(self.reader.adjust(v))
    }

    /// The runtime absolute address of the GOT slot for the symbol. None means a parse
    /// failure; the vector inside Some may be empty (the symbol was not imported).
    pub fn reloc_slots(&mut self, name: &str) -> Option<Vec<u64>> {
        if !self.ensure() {
            return None;
        }
        let mut r = MemReader {
            pid: self.reader.pid,
            bias: self.reader.bias,
        };
        let (syms, strs) = self.cache.as_ref()?;
        rela_slots(&mut r, &self.tags, syms, strs, name)
    }
}

/// The GNU build-id lives in a read-only PT_NOTE; this returns the vaddr and the content
/// of the descriptor bytes.
pub fn build_id(b: &[u8]) -> Option<(u64, Vec<u8>)> {
    elf64(b)?;
    let phoff = get!(b, 0x20, u64);
    let phent = get!(b, 0x36, u16) as u64;
    let phnum = get!(b, 0x38, u16) as u64;
    for i in 0..phnum {
        let p = phoff + i * phent;
        if get!(b, p, u32) != 4 {
            continue;
        }
        let off = get!(b, p + 8, u64) as usize;
        let va = get!(b, p + 16, u64);
        let len = get!(b, p + 32, u64) as usize;
        let notes = b.get(off..off.checked_add(len)?)?;
        let mut at = 0usize;
        while at.checked_add(12)? <= notes.len() {
            let name_n = rd32(notes, at) as usize;
            let desc_n = rd32(notes, at + 4) as usize;
            let kind = rd32(notes, at + 8);
            let name = at.checked_add(12)?;
            let desc = name.checked_add(name_n.checked_add(3)? & !3)?;
            let end = desc.checked_add(desc_n)?;
            if kind == 3 && notes.get(name..name.checked_add(name_n)?)? == b"GNU\0" && desc_n > 0 {
                return Some((va + desc as u64, notes.get(desc..end)?.to_vec()));
            }
            at = end.checked_add(3)? & !3;
        }
    }
    None
}
