//! BPF ELF subset loader (the contract is defined in D4 of docs/ebpf-monitor.md):
//! - Sections: the program sections (PROGBITS+X, with the list of names supplied by the
//!   caller), plus "maps" and symtab/strtab/rela. Any other section carrying
//!   SHF_ALLOC+EXECINSTR is fail-closed the moment it appears.
//! - Map definitions: a struct bpf_map_def (20 bytes) inside the "maps" section, located
//!   through an OBJECT symbol.
//! - Relocations: only R_BPF_64_64 targeting a map symbol (type 1, with the addend required
//!   to be 0) is accepted; at load time the loader rewrites the target ld_imm64 to
//!   BPF_PSEUDO_MAP_FD. Every other type is rejected.
use std::os::unix::io::RawFd;
use std::sync::Mutex;

const EM_BPF: u16 = 247;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9; // BPF targets actually emit REL (16-byte entries with no addend)
const SHF_EXECINSTR: u64 = 0x4;
const R_BPF_64_64: u32 = 1;

const BPF_LD_IMM_DW: u8 = 0x18; // BPF_LD | BPF_DW | BPF_IMM
const BPF_PSEUDO_MAP_FD: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Insn {
    pub code: u8,
    pub regs: u8, // the low 4 bits hold dst, the high 4 bits hold src
    pub off: i16,
    pub imm: i32,
}

struct Section {
    name: String,
    sh_type: u32,
    sh_flags: u64,
    off: u64,
    size: u64,
    link: u32,
    info: u32,
    entsize: u64,
}

pub struct MapDef {
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

pub struct ProgDef {
    pub section: String,
    pub insns: Vec<Insn>,
    /// (instruction index, map name) -- the patch point where ld_imm64 becomes a pseudo-fd
    pub relocs: Vec<(usize, String)>,
}

pub struct Parsed {
    pub maps: Vec<MapDef>,
    pub progs: Vec<ProgDef>,
}

/// A wrapper that owns an fd and closes it on Drop. The Mutex exists only so that mod.rs can
/// hold the wrapper by value while still being able to take the i32 out at any time.
pub struct LoadedMap {
    pub name: String,
    pub fd: Mutex<Option<RawFd>>,
}
impl Drop for LoadedMap {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.lock().ok().and_then(|mut g| g.take()) {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
pub struct ProgFd {
    pub section: String,
    pub fd: Mutex<Option<RawFd>>,
}
impl Drop for ProgFd {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.lock().ok().and_then(|mut g| g.take()) {
            unsafe {
                libc::close(fd);
            }
        }
    }
}
/// The link fd returned by bpf_raw_tracepoint_open; closing it detaches the probe.
pub struct RawTpLink {
    pub fd: Mutex<Option<RawFd>>,
}
impl Drop for RawTpLink {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.lock().ok().and_then(|mut g| g.take()) {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_ne_bytes(b[o..o + 2].try_into().unwrap())
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_ne_bytes(b[o..o + 4].try_into().unwrap())
}
fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_ne_bytes(b[o..o + 8].try_into().unwrap())
}

fn cstr_at(b: &[u8], off: usize) -> Option<String> {
    if off >= b.len() {
        return None;
    }
    let end = off + b[off..].iter().position(|&c| c == 0)?;
    Some(String::from_utf8_lossy(&b[off..end]).into_owned())
}

/// Parse the object. A program section is any PROGBITS|EXEC section whose name carries the
/// "raw_tp/" prefix; any other executable section is fail-closed.
pub fn parse(object: &[u8]) -> Result<Parsed, String> {
    let sections = parse_sections(object)?;

    let mut maps_sec_idx: Option<usize> = None;
    let mut symtab: Option<(usize, usize, usize)> = None; // (offset, size, strtab section index)
    let mut symtab_idx = usize::MAX;
    for (idx, s) in sections.iter().enumerate() {
        match (s.sh_type, s.name.as_str()) {
            (SHT_PROGBITS, "maps") => maps_sec_idx = Some(idx),
            (SHT_SYMTAB, _) => {
                symtab = Some((s.off as usize, s.size as usize, s.link as usize));
                symtab_idx = idx;
            }
            _ => {}
        }
    }
    let maps_sec_idx = maps_sec_idx.ok_or("missing maps section")?;
    let symtab = symtab.ok_or("missing .symtab(compile keeping the symbol table)")?;
    let strsec = sections.get(symtab.2).ok_or("symtab->strtab chain invalid")?;
    if strsec.sh_type != SHT_STRTAB {
        return Err("symtab->strtab chain invalid".into());
    }
    let strtab = &object[strsec.off as usize..(strsec.off + strsec.size) as usize];

    // Map symbols are the OBJECT symbols that fall inside the maps section.
    let maps_sec = &sections[maps_sec_idx];
    let maps_data = &object[maps_sec.off as usize..(maps_sec.off + maps_sec.size) as usize];
    let mut maps = Vec::new();
    let mut map_names: Vec<String> = Vec::new();
    for j in 0..(symtab.1 / 24) {
        let s = symtab.0 + j * 24;
        let st_name = rd32(object, s) as usize;
        let st_info = object[s + 4];
        let st_shndx = rd16(object, s + 6) as usize;
        let st_value = rd64(object, s + 8);
        let st_size = rd64(object, s + 16);
        if st_shndx != maps_sec_idx || st_size != 20 || (st_info & 0xf) != 1 {
            continue; // OBJECT (type 1); global or local binding is both acceptable
        }
        let name = cstr_at(strtab, st_name).ok_or("map symbol name invalid")?;
        let d = st_value as usize;
        if d + 20 > maps_data.len() {
            return Err(format!("map {name} out of range"));
        }
        maps.push(MapDef {
            name: name.clone(),
            map_type: rd32(maps_data, d),
            key_size: rd32(maps_data, d + 4),
            value_size: rd32(maps_data, d + 8),
            max_entries: rd32(maps_data, d + 12),
            map_flags: rd32(maps_data, d + 16),
        });
        map_names.push(name);
    }
    if maps.is_empty() {
        return Err("no map symbols in the maps section".into());
    }

    // A program section is a PROGBITS|EXEC section with the "raw_tp/" prefix; that is the only
    // kind this CLI consumes.
    let mut progs = Vec::new();
    for (idx, s) in sections.iter().enumerate() {
        if s.sh_type != SHT_PROGBITS || s.sh_flags & SHF_EXECINSTR == 0 || s.size == 0 {
            continue; // clang leaves an empty .text behind; let it through
        }
        if !s.name.starts_with("raw_tp/") {
            return Err(format!(
                "executable section {} outside the contract (fail-closed, see docs D4)",
                s.name
            ));
        }
        let raw = &object[s.off as usize..(s.off + s.size) as usize];
        if raw.len() % 8 != 0 {
            return Err(format!("section {} instructions not 8-byte aligned", s.name));
        }
        // SAFETY: Insn has a flat repr(C) layout and the length is already 8-byte aligned. The
        // byte buffer itself is not guaranteed to be aligned, so each instruction is read
        // individually with read_unaligned.
        let insns = (0..raw.len() / 8)
            .map(|i| unsafe { std::ptr::read_unaligned(raw.as_ptr().add(i * 8) as *const Insn) })
            .collect::<Vec<Insn>>();
        // Relocations belonging to this section (.rel/.rela: link points at the symtab and
        // info points at the target section)
        let mut relocs = Vec::new();
        for r in &sections {
            if (r.sh_type != SHT_RELA && r.sh_type != SHT_REL) || r.link as usize != symtab_idx {
                continue;
            }
            if r.info as usize != idx {
                continue;
            }
            let data = &object[r.off as usize..(r.off + r.size) as usize];
            let es = if r.entsize == 0 {
                if r.sh_type == SHT_RELA { 24 } else { 16 }
            } else {
                r.entsize as usize
            };
            for e in data.chunks_exact(es) {
                let r_offset = rd64(e, 0);
                let r_info = rd64(e, 8);
                let rtype = (r_info & 0xffff_ffff) as u32;
                let sym = (r_info >> 32) as usize;
                if rtype != R_BPF_64_64 {
                    return Err(format!(
                        "section {} has relocation type {rtype} outside the contract (only R_BPF_64_64 supported)",
                        s.name
                    ));
                }
                if r.sh_type == SHT_RELA && rd64(e, 16) != 0 {
                    return Err(format!("section {} map relocation addend is non-zero", s.name));
                }
                let sname = sym_name(object, symtab, strtab, sym)
                    .ok_or_else(|| format!("relocation symbol {sym} has no name"))?;
                if !map_names.contains(&sname) {
                    return Err(format!(
                        "relocation target {sname} is not a map symbol (contract: map references only)"
                    ));
                }
                let insn_idx = (r_offset / 8) as usize;
                relocs.push((insn_idx, sname));
            }
        }
        progs.push(ProgDef {
            section: s.name.clone(),
            insns,
            relocs,
        });
    }
    if progs.is_empty() {
        return Err("no raw_tp/* program sections in the object".into());
    }
    Ok(Parsed { maps, progs })
}

fn sym_name(
    object: &[u8],
    symtab: (usize, usize, usize),
    strtab: &[u8],
    idx: usize,
) -> Option<String> {
    let s = symtab.0.checked_add(idx.checked_mul(24)?)?;
    if s + 24 > object.len() || idx * 24 >= symtab.1 {
        return None;
    }
    let st_name = rd32(object, s) as usize;
    cstr_at(strtab, st_name)
}

fn parse_sections(object: &[u8]) -> Result<Vec<Section>, String> {
    if object.is_empty() {
        return Err("monitor.bpf.o not embedded (run ./build.sh first)".into());
    }
    if object.len() < 64 || &object[0..4] != b"\x7fELF" {
        return Err("not ELF".into());
    }
    if object[4] != 2 || object[5] != 1 {
        return Err("only ELF64 little-endian supported".into());
    }
    if rd16(object, 0x12) != EM_BPF {
        return Err("not a BPF object file".into());
    }
    let shoff = rd64(object, 0x28) as usize;
    let shentsize = rd16(object, 0x3A) as usize;
    let shnum = rd16(object, 0x3C) as usize;
    let shstrndx = rd16(object, 0x3E) as usize;
    if shoff == 0 || shnum == 0 || shentsize < 64 {
        return Err("no section headers (do not strip section headers when compiling)".into());
    }
    let mut raw = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if sh + shentsize > object.len() {
            return Err("section header out of range".into());
        }
        raw.push((
            rd32(object, sh) as usize,          // sh_name
            rd32(object, sh + 4),               // sh_type
            rd64(object, sh + 8),               // sh_flags
            rd64(object, sh + 24),              // sh_offset
            rd64(object, sh + 32),              // sh_size
            rd32(object, sh + 40),              // sh_link
            rd32(object, sh + 44),              // sh_info
            rd64(object, sh + 56),              // sh_entsize
        ));
    }
    let (str_off, str_size) = {
        let s = raw.get(shstrndx).ok_or("e_shstrndx invalid")?;
        (s.3 as usize, s.4 as usize)
    };
    let shstr = object
        .get(str_off..str_off + str_size)
        .ok_or("shstrtab out of range")?;
    let mut sections = Vec::with_capacity(shnum);
    for (name, sh_type, sh_flags, off, size, link, info, entsize) in raw {
        let name = cstr_at(shstr, name).unwrap_or_default();
        sections.push(Section {
            name,
            sh_type,
            sh_flags,
            off,
            size,
            link,
            info,
            entsize,
        });
    }
    Ok(sections)
}

/// Rewrite the ld_imm64 at insns[idx] into a pseudo-fd reference (the imm of the following
/// instruction is zeroed as well).
pub fn patch_map_fd(insns: &mut [Insn], idx: usize, fd: RawFd) -> Result<(), String> {
    let i = insns.get_mut(idx).ok_or("relocation points to a nonexistent instruction")?;
    if i.code != BPF_LD_IMM_DW {
        return Err(format!(
            "relocation target instruction {idx} is not ld_imm64(code={:#x})",
            i.code
        ));
    }
    i.regs = (i.regs & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
    i.imm = fd;
    if let Some(next) = insns.get_mut(idx + 1) {
        next.imm = 0;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insn_layout_is_8_bytes() {
        assert_eq!(std::mem::size_of::<Insn>(), 8);
    }

    #[test]
    fn patch_sets_pseudo_fd() {
        let mut insns = vec![
            Insn { code: 0x18, regs: 0x01, off: 0, imm: 0 },
            Insn { code: 0, regs: 0, off: 0, imm: -1 },
        ];
        patch_map_fd(&mut insns, 0, 42).unwrap();
        assert_eq!(insns[0].regs >> 4, 1);
        assert_eq!(insns[0].imm, 42);
        assert_eq!(insns[1].imm, 0);
        assert!(patch_map_fd(&mut insns, 5, 1).is_err());
    }

    /// Parsing of the real artifact: when the build.sh output exists, verify the subset
    /// contract against it.
    #[test]
    fn parses_real_object() {
        let object = super::super::BPF_OBJECT;
        if object.is_empty() {
            eprintln!("skip: out/monitor.bpf.o not built");
            return;
        }
        let parsed = parse(object).unwrap();
        assert_eq!(parsed.progs.len(), 2);
        assert!(parsed.maps.iter().any(|m| m.name == "events_map"));
        let names: Vec<&str> = parsed.progs.iter().map(|p| p.section.as_str()).collect();
        assert!(names.contains(&"raw_tp/sys_enter"));
        assert!(names.contains(&"raw_tp/sys_exit"));
        for p in &parsed.progs {
            assert!(!p.relocs.is_empty());
            for (idx, _) in &p.relocs {
                assert_eq!(p.insns[*idx].code, 0x18);
            }
        }
    }
}
