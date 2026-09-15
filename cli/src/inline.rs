//! Native function hooks; distinct from ART's `hook` API.
use crate::ctl::{check_status, rd32, rd64, wr32, wr64, Outcome, Ring};
use crate::json::Json;
use crate::proto;

const INIT: u32 = 40;
const ADD: u32 = 41;
const DEL: u32 = 42;
pub(crate) const LIST: u32 = 43;
const QUERY: u32 = 44;
const RECORD_SIZE: usize = 48;

#[derive(Debug)]
struct Address {
    name: String,
    module: Option<String>,
}
impl Address {
    fn new(name: &str, module: Option<&str>) -> Result<Self, String> {
        if name.starts_with("0x") || name.starts_with("0X") {
            address_number(name)?;
        } else if name.is_empty() || module.is_none() {
            return Err(format!("symbol {name:?} requires a module selector"));
        }
        if module.is_some_and(|s| s.is_empty()) {
            return Err("module selector must not be empty".into());
        }
        Ok(Self {
            name: name.into(),
            module: module.map(str::to_owned),
        })
    }
    fn resolve(&self, pid: i32) -> Result<u64, String> {
        if self.name.starts_with("0x") || self.name.starts_with("0X") {
            return address_number(&self.name);
        }
        let module = self.module.as_deref().unwrap();
        let maps = crate::procfs::maps(pid).map_err(|e| e.to_string())?;
        let matches: Vec<_> = maps
            .iter()
            .filter(|m| m.off == 0 && m.path.ends_with(module))
            .collect();
        if matches.len() != 1 {
            return Err(format!(
                "module {module:?} matched {} mappings; use an unambiguous path or address",
                matches.len()
            ));
        }
        let mapping = matches[0];
        let addr = crate::elf::sym_vaddr(std::path::Path::new(&mapping.path), &self.name)
            .and_then(|off| mapping.start.checked_add(off))
            .or_else(|| {
                crate::elf::MemElf::load(pid, mapping.start)
                    .and_then(|mut elf| elf.sym_addr(&self.name))
            })
            .ok_or_else(|| format!("symbol {} not found in {}", self.name, mapping.path))?;
        Ok(addr)
    }
}
fn address_number(s: &str) -> Result<u64, String> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
    let n = hex
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .ok_or_else(|| format!("invalid address: {s}; use 0xHEX"))?;
    if n == 0 {
        return Err("address must be nonzero".into());
    }
    Ok(n)
}
fn id(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        return address_number(s);
    }
    s.parse::<u64>()
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(|| format!("invalid hook id: {s}"))
}

#[derive(Debug)]
pub struct Command(Action);
#[derive(Debug)]
enum Action {
    Init,
    Add {
        target: Address,
        replacement: Address,
        original_slot: Option<Address>,
    },
    Del(u64),
    List,
    Query(u64),
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
            ["inline", "init"] => Action::Init,
            ["inline", "list"] => Action::List,
            ["inline", "query", n] => Action::Query(id(n)?),
            ["inline", "del", n] => Action::Del(id(n)?),
            ["inline", "add", rest @ ..] => {
                if rest.len() % 2 != 0 { return Err("inline add options require values".into()); }
                let mut opts = std::collections::BTreeMap::new();
                for pair in rest.chunks_exact(2) {
                    if !matches!(pair[0], "--target" | "--replacement" | "--original-slot" | "--in" | "--replacement-in")
                        || opts.insert(pair[0], pair[1]).is_some() {
                        return Err(format!("unknown/duplicate inline option: {}", pair[0]));
                    }
                }
                let target = Address::new(opts.get("--target").ok_or("missing --target")?, opts.get("--in").copied())?;
                let replacement = Address::new(opts.get("--replacement").ok_or("missing --replacement")?, opts.get("--replacement-in").copied())?;
                let original_slot = opts.get("--original-slot").map(|s| Address::new(s, opts.get("--replacement-in").copied())).transpose()?;
                Action::Add { target, replacement, original_slot }
            }
            _ => return Err("usage: inline init | add --target ADDR/SYM [--in LIB] --replacement ADDR/SYM [--replacement-in LIB] [--original-slot ADDR/SYM] | list | query ID | del ID".into()),
        }))
    }
    pub fn run(self, ring: &mut Ring) -> Result<Outcome, String> {
        let (kind, addr, replacement, slot) = match self.0 {
            Action::Init => (INIT, 0, 0, 0),
            Action::List => (LIST, 0, 0, 0),
            Action::Query(n) => (QUERY, n, 0, 0),
            Action::Del(n) => (DEL, n, 0, 0),
            Action::Add {
                target,
                replacement,
                original_slot,
            } => (
                ADD,
                target.resolve(ring.pid)?,
                replacement.resolve(ring.pid)?,
                original_slot
                    .map(|s| s.resolve(ring.pid))
                    .transpose()?
                    .unwrap_or(0),
            ),
        };
        let r = ring.rpc(|c| {
            wr32(c, proto::C_TYPE, kind);
            wr64(c, proto::C_ADDR, addr);
            wr64(c, proto::C_ARGS, replacement);
            wr64(c, proto::C_ARGS + 8, slot);
        })?;
        check_status(&r)?;
        if kind == INIT {
            let text = String::from_utf8_lossy(&r.data).into_owned();
            let data = Json::Raw(text.clone());
            return Ok(Outcome::new(format!("{}\n", text.trim_end()), data));
        }
        let records = decode(&r.data)?;
        if kind != LIST && records.len() != 1 {
            return Err("invalid inline response record count".into());
        }
        let human = records
            .iter()
            .map(|r| r.to_string() + "\n")
            .collect::<String>();
        let data = if kind == LIST {
            Json::Obj(vec![
                ("records".into(), Json::Arr(records)),
                ("truncated".into(), Json::Bool(false)),
            ])
        } else {
            records.into_iter().next().unwrap_or(Json::Null)
        };
        Ok(Outcome::new(human, data))
    }
}

pub(crate) fn decode(data: &[u8]) -> Result<Vec<Json>, String> {
    if data.len() % RECORD_SIZE != 0 {
        return Err("truncated inline hook record".into());
    }
    data.chunks_exact(RECORD_SIZE)
        .map(|r| {
            let state = match rd32(r, 40) {
                1 => "ACTIVE",
                2 => "REMOVED",
                3 => "ERROR",
                _ => return Err("unknown inline hook state".into()),
            };
            Ok(Json::Obj(vec![
                ("id".into(), Json::UInt(rd64(r, 0))),
                ("target".into(), Json::hex(rd64(r, 8))),
                ("replacement".into(), Json::hex(rd64(r, 16))),
                ("original".into(), Json::hex(rd64(r, 24))),
                ("original_slot".into(), Json::hex(rd64(r, 32))),
                ("state".into(), Json::text(state)),
                ("backend_error".into(), Json::Int(rd32(r, 44) as i32 as i64)),
            ]))
        })
        .collect()
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
    #[test]
    fn malformed_commands_never_submit_rpc() {
        for text in [
            "inline add --target 0x0 --replacement 0x20",
            "inline add --target 0x10 --replacement 0x20 --target 0x30",
            "inline add --target symbol --replacement 0x20",
            "inline add --target 0x10 --replacement 0x20 --typo 1",
            "inline add --target 0x10 --replacement",
            "inline query 0",
            "inline del 1 extra",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }
    #[test]
    fn accepts_addresses_and_explicit_symbol_modules() {
        assert!(parse("inline add --target 0x10 --replacement 0X20 --original-slot 0x30").is_ok());
        assert!(parse("inline add --target func --in /lib.so --replacement proxy --replacement-in /proxy.so --original-slot orig").is_ok());
        for text in [
            "inline init",
            "inline list",
            "inline query 1",
            "inline del 0x10",
        ] {
            assert!(parse(text).is_ok());
        }
    }
    #[test]
    fn rejects_partial_or_unknown_records() {
        assert!(decode(&[0; 47]).is_err());
        assert!(decode(&[0; 48]).is_err());
        let mut r = [0; 48];
        wr64(&mut r, 0, 7);
        wr32(&mut r, 40, 2);
        // The human-readable output is the compact form of this JSON, with a stable field
        // order.
        assert_eq!(
            decode(&r).unwrap()[0].to_string(),
            "{\"id\":7,\"target\":\"0x0\",\"replacement\":\"0x0\",\"original\":\"0x0\",\"original_slot\":\"0x0\",\"state\":\"REMOVED\",\"backend_error\":0}"
        );
    }
}
