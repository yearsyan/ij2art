//! Upload a native library into the target process and dlopen/dlclose it over
//! the control ring. Bytes are staged in a memfd and loaded from
//! /proc/self/fd/N, so the module appears in maps as `/memfd:NAME (deleted)`;
//! pass that string as `--in`/`--replacement-in` to resolve its symbols.
use crate::art::{request, request_args};
use crate::ctl::{rd32, rd64, Outcome, Ring};
use crate::json::Json;
use crate::proto;
use std::io::Read;

pub const BEGIN: u32 = 50;
pub const CHUNK: u32 = 51;
pub const COMMIT: u32 = 52;
pub const UNLOAD: u32 = 53;
pub const LIST: u32 = 54;
pub const LIB_MAX: usize = 4 * 1024 * 1024;
pub const NAME_MAX: usize = 48;
pub const INFO_SIZE: usize = 128;

#[derive(Debug, PartialEq, Eq)]
pub struct LibInfo {
    pub id: u64,
    pub nonce: u64,
    pub size: u64,
    pub received: u64,
    pub base: u64,
    pub handle: u64,
    pub state: u32,
    pub error: i32,
    pub name: String,
}
impl LibInfo {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != INFO_SIZE {
            return Err("invalid library record length".into());
        }
        let name_bytes = &bytes[56..120];
        let end = name_bytes
            .iter()
            .position(|&b| b == 0)
            .ok_or("library record name is not NUL-terminated")?;
        let name = std::str::from_utf8(&name_bytes[..end])
            .map_err(|_| "library record name is not UTF-8")?
            .to_owned();
        let value = Self {
            id: rd64(bytes, 0),
            nonce: rd64(bytes, 8),
            size: rd64(bytes, 16),
            received: rd64(bytes, 24),
            base: rd64(bytes, 32),
            handle: rd64(bytes, 40),
            state: rd32(bytes, 48),
            error: rd32(bytes, 52) as i32,
            name,
        };
        if value.id == 0
            || value.nonce == 0
            || !(1..=4).contains(&value.state)
            || value.size > LIB_MAX as u64
            || value.received > value.size
        {
            return Err("invalid library record fields".into());
        }
        Ok(value)
    }
    /// maps path suffix usable as `--in`/`--replacement-in` module selector.
    fn module(&self) -> String {
        format!("/memfd:{} (deleted)", self.name)
    }
}
fn state_name(state: u32) -> &'static str {
    match state {
        1 => "UPLOADING",
        2 => "LOADED",
        3 => "FAILED",
        _ => "UNLOADED",
    }
}
/// The JSON shape of a record; the human-readable output is its compact rendering, with a
/// stable field order.
pub(crate) fn info_json(info: &LibInfo) -> Json {
    Json::Obj(vec![
        ("id".into(), Json::UInt(info.id)),
        ("nonce".into(), Json::UInt(info.nonce)),
        ("size".into(), Json::UInt(info.size)),
        ("received".into(), Json::UInt(info.received)),
        ("base".into(), Json::hex(info.base)),
        ("handle".into(), Json::hex(info.handle)),
        ("state".into(), Json::text(state_name(info.state))),
        ("error".into(), Json::Int(info.error as i64)),
        ("name".into(), Json::text(info.name.clone())),
        ("module".into(), Json::text(info.module())),
    ])
}
pub(crate) fn list_json(data: &[u8]) -> Result<Vec<Json>, String> {
    if data.len() % INFO_SIZE != 0 {
        return Err("invalid/truncated library list".into());
    }
    data.chunks_exact(INFO_SIZE)
        .map(|b| LibInfo::decode(b).map(|i| info_json(&i)))
        .collect()
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > NAME_MAX
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("library name must be 1..48 of [A-Za-z0-9._-]".into());
    }
    Ok(())
}

/// Client-side transport check; the payload re-validates and dlopen does the rest.
fn validate_elf(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 64
        || bytes.len() > LIB_MAX
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2  // ELFCLASS64
        || bytes[5] != 1  // little endian
        || bytes[6] != 1  // EV_CURRENT
        || bytes[16..18] != [3, 0]   // ET_DYN
        || bytes[18..20] != [183, 0] // EM_AARCH64
    {
        return Err("expected an arm64 ELF64 shared object (ET_DYN), at most 4 MiB".into());
    }
    Ok(())
}

fn id(text: &str) -> Result<u64, String> {
    let value = if text.starts_with("0x") || text.starts_with("0X") {
        u64::from_str_radix(&text[2..], 16)
    } else {
        text.parse()
    }
    .map_err(|_| format!("invalid library id: {text}"))?;
    if value == 0 {
        return Err("library id must be nonzero".into());
    }
    Ok(value)
}

fn nonce() -> Result<u64, String> {
    let mut bytes = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| e.to_string())?;
    Ok(u64::from_ne_bytes(bytes).max(1))
}

fn commit(ring: &mut Ring, id: u64) -> Result<LibInfo, String> {
    let info = LibInfo::decode(&request(ring, COMMIT, id, 0, &[])?.data)?;
    if info.id != id || info.state != 2 {
        return Err("commit did not return a loaded library".into());
    }
    Ok(info)
}

/// BEGIN is keyed by nonce: a retry after an uncertain timeout resumes the same
/// record, replayed chunks are verified against the staged bytes payload-side.
fn upload(ring: &mut Ring, bytes: &[u8], name: &str, nonce: u64) -> Result<LibInfo, String> {
    let response = request_args(ring, BEGIN, &[nonce, bytes.len() as u64], name.as_bytes())?;
    let info = LibInfo::decode(&response.data)?;
    if info.nonce != nonce || info.size != bytes.len() as u64 || info.name != name {
        return Err("upload response identity mismatch".into());
    }
    match info.state {
        2 => return Ok(info), // a previous attempt already committed
        1 => {}
        _ => {
            return Err(format!(
                "nonce {} is bound to a {} record; rerun with a fresh nonce",
                nonce,
                state_name(info.state)
            ))
        }
    }
    for (n, chunk) in bytes.chunks(proto::CMD_DATA_MAX).enumerate() {
        let response = request(ring, CHUNK, info.id, (n * proto::CMD_DATA_MAX) as u64, chunk)?;
        let updated = LibInfo::decode(&response.data)?;
        if updated.id != info.id {
            return Err("library chunk identity mismatch".into());
        }
    }
    commit(ring, info.id)
}

#[derive(Debug)]
pub struct Command(Action);
#[derive(Debug)]
enum Action {
    Load {
        path: String,
        name: Option<String>,
        nonce: u64,
    },
    Commit(u64),
    Unload(u64),
    List,
}
impl Command {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut words = Vec::new();
        let mut it = args.iter().skip(2);
        while let Some(word) = it.next() {
            if matches!(word.as_str(), "--pid" | "--pkg") {
                it.next().ok_or("missing process selector value")?;
            } else {
                words.push(word.as_str());
            }
        }
        Ok(Self(match words.as_slice() {
            ["lib", "list"] => Action::List,
            ["lib", "commit", n] => Action::Commit(id(n)?),
            ["lib", "unload", n] => Action::Unload(id(n)?),
            ["lib", "load", path, rest @ ..] => {
                if rest.len() % 2 != 0 {
                    return Err("lib load options require values".into());
                }
                let mut name = None;
                let mut key = None;
                for pair in rest.chunks_exact(2) {
                    match pair[0] {
                        "--name" if name.is_none() => {
                            validate_name(pair[1])?;
                            name = Some(pair[1].to_string());
                        }
                        "--nonce" if key.is_none() => key = Some(id(pair[1])?),
                        _ => return Err(format!("unknown/duplicate lib option: {}", pair[0])),
                    }
                }
                Action::Load {
                    path: (*path).into(),
                    name,
                    nonce: match key {
                        Some(n) => n,
                        None => nonce()?,
                    },
                }
            }
            _ => {
                return Err(
                    "usage: lib load <file.so> [--name N] [--nonce N] | commit ID | unload ID | list"
                        .into(),
                )
            }
        }))
    }
    pub fn run(self, ring: &mut Ring) -> Result<Outcome, String> {
        match self.0 {
            Action::Load { path, name, nonce } => {
                let file = std::fs::File::open(&path).map_err(|e| format!("{path}: {e}"))?;
                let mut bytes = Vec::new();
                file.take(LIB_MAX as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                validate_elf(&bytes)?;
                let name = match name {
                    Some(n) => n,
                    None => {
                        let base = path
                            .rsplit('/')
                            .next()
                            .ok_or("cannot derive a library name; pass --name")?;
                        validate_name(base)
                            .map_err(|_| format!("file name {base:?} is not usable; pass --name"))?;
                        base.to_owned()
                    }
                };
                eprintln!("upload_nonce={nonce}; timeout recovery: lib list, then lib load with --nonce {nonce} or lib commit ID");
                let info = upload(ring, &bytes, &name, nonce)?;
                eprintln!("[*] module selector for --in/--replacement-in: {}", info.module());
                let data = info_json(&info);
                Ok(Outcome::new(data.to_string() + "\n", data))
            }
            Action::Commit(id) => {
                let data = info_json(&commit(ring, id)?);
                Ok(Outcome::new(data.to_string() + "\n", data))
            }
            Action::Unload(id) => {
                let info = LibInfo::decode(&request(ring, UNLOAD, id, 0, &[])?.data)?;
                let data = info_json(&info);
                Ok(Outcome::new(data.to_string() + "\n", data))
            }
            Action::List => {
                let response = request(ring, LIST, 0, 0, &[])?;
                let records = list_json(&response.data)?;
                let truncated = response.flags & 1 != 0;
                let mut human = records
                    .iter()
                    .map(|r| r.to_string() + "\n")
                    .collect::<String>();
                if truncated {
                    human.push_str("[!] list truncated (response slot full)\n");
                }
                Ok(Outcome::new(
                    human,
                    Json::Obj(vec![
                        ("records".into(), Json::Arr(records)),
                        ("truncated".into(), Json::Bool(truncated)),
                    ]),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(words: &str) -> Result<Command, String> {
        Command::parse(
            &format!("ij2art ctl --pid 123 {words}")
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
    }
    fn record(id: u64, state: u32, name: &str) -> [u8; INFO_SIZE] {
        let mut r = [0u8; INFO_SIZE];
        wr64_at(&mut r, 0, id);
        wr64_at(&mut r, 8, 7); // nonce
        wr64_at(&mut r, 16, 4096); // size
        wr32_at(&mut r, 48, state);
        r[56..56 + name.len()].copy_from_slice(name.as_bytes());
        r
    }
    fn wr64_at(b: &mut [u8], off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_ne_bytes());
    }
    fn wr32_at(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    }
    #[test]
    fn malformed_commands_never_submit_rpc() {
        for text in [
            "lib load",
            "lib load /a.so --name",
            "lib load /a.so --typo 1",
            "lib load /a.so --name x --name y",
            "lib load /a.so --nonce 0",
            "lib load /a.so --nonce zz",
            "lib load /a.so --name bad/name",
            "lib commit 0",
            "lib unload 1 extra",
            "lib query 1",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        let long = format!("lib load /a.so --name {}", "x".repeat(49));
        assert!(parse(&long).is_err());
    }
    #[test]
    fn accepts_load_unload_list_commit() {
        match parse("lib load /data/local/tmp/p.so").unwrap().0 {
            Action::Load { path, name, nonce } => {
                assert_eq!(path, "/data/local/tmp/p.so");
                assert_eq!(name, None);
                assert!(nonce != 0);
            }
            _ => panic!("expected load"),
        }
        match parse("lib load /p.so --name proxy.v2 --nonce 0x10").unwrap().0 {
            Action::Load { name, nonce, .. } => {
                assert_eq!(name.as_deref(), Some("proxy.v2"));
                assert_eq!(nonce, 0x10);
            }
            _ => panic!("expected load"),
        }
        assert!(matches!(parse("lib list").unwrap().0, Action::List));
        assert!(matches!(parse("lib commit 7").unwrap().0, Action::Commit(7)));
        assert!(matches!(parse("lib unload 0x9").unwrap().0, Action::Unload(9)));
    }
    #[test]
    fn decode_rejects_bad_records() {
        assert!(LibInfo::decode(&[0; 127]).is_err());
        assert!(LibInfo::decode(&record(0, 2, "x")).is_err()); // id 0
        let mut bad = record(1, 9, "x");
        assert!(LibInfo::decode(&bad).is_err());
        bad = record(1, 2, "x");
        wr64_at(&mut bad, 24, 8192); // received > size
        assert!(LibInfo::decode(&bad).is_err());
        let mut ok = record(3, 4, "uplfix");
        wr64_at(&mut ok, 32, 0x7000);
        let info = LibInfo::decode(&ok).unwrap();
        assert_eq!(info.state, 4);
        assert_eq!(info.module(), "/memfd:uplfix (deleted)");
        let mut nonnul = record(1, 2, "x");
        nonnul[56..120].fill(b'a');
        assert!(LibInfo::decode(&nonnul).is_err());
    }
    #[test]
    fn record_json_is_byte_stable() {
        let mut r = record(3, 2, "uplfix");
        wr64_at(&mut r, 24, 4096);
        wr64_at(&mut r, 32, 0x7000);
        wr64_at(&mut r, 40, 0x1234);
        let info = LibInfo::decode(&r).unwrap();
        assert_eq!(
            info_json(&info).to_string(),
            "{\"id\":3,\"nonce\":7,\"size\":4096,\"received\":4096,\"base\":\"0x7000\",\"handle\":\"0x1234\",\"state\":\"LOADED\",\"error\":0,\"name\":\"uplfix\",\"module\":\"/memfd:uplfix (deleted)\"}"
        );
    }
    #[test]
    fn elf_header_validation() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16] = 3;
        elf[18] = 183;
        validate_elf(&elf).unwrap();
        elf[4] = 1; // 32-bit
        assert!(validate_elf(&elf).is_err());
        elf[4] = 2;
        elf[16] = 2; // ET_EXEC
        assert!(validate_elf(&elf).is_err());
        elf[16] = 3;
        elf[18] = 62; // x86-64
        assert!(validate_elf(&elf).is_err());
        assert!(validate_elf(&elf[..32]).is_err());
    }
}
