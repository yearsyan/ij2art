//! Instruction observation points. Wire layout mirrors common/probe_proto.h.
use crate::ctl::{check_status, rd32, rd64, wr32, wr64, Outcome, Ring};
use crate::inline::Address;
use crate::json::Json;
use crate::proto;
use std::collections::BTreeMap;

const ADD: u32 = 70;
const DEL: u32 = 71;
pub(crate) const LIST: u32 = 72;
const QUERY: u32 = 73;
const READ: u32 = 74;
const INFO_SIZE: usize = 88;
const BATCH_SIZE: usize = 112;
const EVENT_SIZE: usize = 304;
const READ_MAX: u64 = 48;
const NO_CONDITION: u32 = u32::MAX;

fn number(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|_| format!("invalid number: {s}"))
    } else {
        s.parse().map_err(|_| format!("invalid number: {s}"))
    }
}
fn id(s: &str) -> Result<u64, String> {
    number(s).and_then(|n| {
        if n > 0 {
            Ok(n)
        } else {
            Err("probe id must be nonzero".into())
        }
    })
}
fn options<'a>(words: &[&'a str], allowed: &[&str]) -> Result<BTreeMap<&'a str, &'a str>, String> {
    if words.len() % 2 != 0 {
        return Err("probe options require values".into());
    }
    let mut opts = BTreeMap::new();
    for pair in words.chunks_exact(2) {
        if !allowed.contains(&pair[0]) || opts.insert(pair[0], pair[1]).is_some() {
            return Err(format!("unknown/duplicate probe option: {}", pair[0]));
        }
    }
    Ok(opts)
}
fn condition(s: &str) -> Result<(u32, u64), String> {
    let (reg, value) = s.split_once('=').ok_or("--when expects xN=VALUE")?;
    let reg = reg
        .strip_prefix('x')
        .and_then(|n| n.parse::<u32>().ok())
        .filter(|n| *n <= 30)
        .ok_or("--when register must be x0..x30")?;
    Ok((reg, number(value)?))
}

#[derive(Debug)]
pub struct Command(Action);
#[derive(Debug)]
enum Action {
    Add {
        target: Option<Address>,
        module: Option<String>,
        offset: u64,
        tid: u32,
        max_hits: u64,
        condition: (u32, u64),
    },
    List,
    Query(u64),
    Del(u64),
    Read {
        id: u64,
        after: u64,
        limit: u64,
    },
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
            ["probe", "list"] => Action::List,
            ["probe", "query", n] => Action::Query(id(n)?),
            ["probe", "del", n] => Action::Del(id(n)?),
            ["probe", "read", n, rest @ ..] => {
                let opts = options(rest, &["--after", "--limit"])?;
                let after = opts.get("--after").map(|n| number(n)).transpose()?.unwrap_or(0);
                let limit = opts.get("--limit").map(|n| number(n)).transpose()?.unwrap_or(READ_MAX);
                if limit == 0 || limit > READ_MAX { return Err("--limit must be 1..48".into()); }
                Action::Read { id: id(n)?, after, limit }
            }
            ["probe", "add", rest @ ..] => {
                let opts = options(rest, &["--target", "--in", "--offset", "--tid", "--max-hits", "--when"])?;
                let module = opts.get("--in").copied();
                if module == Some("") { return Err("module selector must not be empty".into()); }
                let target = opts.get("--target").map(|n| Address::new(n, module)).transpose()?;
                if target.is_none() && (module.is_none() || !opts.contains_key("--offset")) {
                    return Err("probe add requires --target ADDR/SYM or --in LIB --offset RVA".into());
                }
                if module.is_some() && opts.get("--target").is_some_and(|s| s.starts_with("0x") || s.starts_with("0X")) {
                    return Err("absolute --target cannot use --in; use --offset for an ELF virtual address".into());
                }
                let offset = opts.get("--offset").map(|n| number(n)).transpose()?.unwrap_or(0);
                if offset & 3 != 0 { return Err("--offset must be 4-byte aligned".into()); }
                let tid = opts.get("--tid").map(|n| number(n)).transpose()?.unwrap_or(0);
                if tid > i32::MAX as u64 { return Err("--tid must fit a positive Linux tid (0=any)".into()); }
                let max_hits = opts.get("--max-hits").map(|n| number(n)).transpose()?.unwrap_or(0);
                let condition = opts.get("--when").map(|s| condition(s)).transpose()?.unwrap_or((NO_CONDITION, 0));
                Action::Add { target, module: module.map(str::to_owned), offset, tid: tid as u32, max_hits, condition }
            }
            _ => return Err("usage: probe add (--target ADDR/SYM [--in LIB] | --in LIB --offset RVA) [--offset N] [--tid T] [--max-hits N] [--when xN=VALUE] | list | query ID | del ID | read ID [--after SEQ] [--limit 1..48]".into()),
        }))
    }
    pub fn run(self, ring: &mut Ring) -> Result<Outcome, String> {
        let (kind, addr, args) = match self.0 {
            Action::List => (LIST, 0, [0; 4]),
            Action::Query(n) => (QUERY, n, [0; 4]),
            Action::Del(n) => (DEL, n, [0; 4]),
            Action::Read { id, after, limit } => (READ, id, [after, limit, 0, 0]),
            Action::Add {
                target,
                module,
                offset,
                tid,
                max_hits,
                condition,
            } => {
                let addr = if let Some(target) = target {
                    target
                        .resolve(ring.pid)?
                        .checked_add(offset)
                        .ok_or("instruction address overflow")?
                } else {
                    crate::inline::module_offset(ring.pid, module.as_deref().unwrap(), offset)?
                };
                if addr == 0 || addr & 3 != 0 {
                    return Err("instruction address must be nonzero and 4-byte aligned".into());
                }
                (
                    ADD,
                    addr,
                    [tid as u64, max_hits, condition.0 as u64, condition.1],
                )
            }
        };
        let response = ring.rpc(|c| {
            wr32(c, proto::C_TYPE, kind);
            wr64(c, proto::C_ADDR, addr);
            for (i, arg) in args.iter().enumerate() {
                wr64(c, proto::C_ARGS + i * 8, *arg);
            }
        })?;
        check_status(&response)?;
        if kind == READ {
            let data = decode_batch(&response.data)?;
            return Ok(Outcome::new(data.to_string() + "\n", data));
        }
        let records = decode(&response.data)?;
        if kind != LIST && records.len() != 1 {
            return Err("invalid probe response record count".into());
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
            records.into_iter().next().unwrap()
        };
        Ok(Outcome::new(human, data))
    }
}

fn info(data: &[u8]) -> Result<Json, String> {
    if data.len() != INFO_SIZE {
        return Err("truncated probe record".into());
    }
    let state = match rd32(data, 72) {
        1 => "ACTIVE",
        2 => "REMOVED",
        3 => "ERROR",
        4 => "LIMITED",
        _ => return Err("unknown probe state".into()),
    };
    let reg = rd32(data, 68);
    let condition = if reg == NO_CONDITION {
        Json::Null
    } else if reg <= 30 {
        Json::Obj(vec![
            ("register".into(), Json::text(format!("x{reg}"))),
            ("equals".into(), Json::hex(rd64(data, 56))),
        ])
    } else {
        return Err("invalid probe condition register".into());
    };
    Ok(Json::Obj(vec![
        ("id".into(), Json::UInt(rd64(data, 0))),
        ("target".into(), Json::hex(rd64(data, 8))),
        ("state".into(), Json::text(state)),
        ("tid".into(), Json::UInt(rd32(data, 64) as u64)),
        ("condition".into(), condition),
        ("max_hits".into(), Json::UInt(rd64(data, 16))),
        ("hits".into(), Json::UInt(rd64(data, 24))),
        ("captured".into(), Json::UInt(rd64(data, 32))),
        ("dropped".into(), Json::UInt(rd64(data, 40))),
        ("overwritten".into(), Json::UInt(rd64(data, 48))),
        ("instruction".into(), Json::hex(rd32(data, 80) as u64)),
        ("capacity".into(), Json::UInt(rd32(data, 84) as u64)),
        (
            "backend_error".into(),
            Json::Int(rd32(data, 76) as i32 as i64),
        ),
    ]))
}
pub(crate) fn decode(data: &[u8]) -> Result<Vec<Json>, String> {
    if data.len() % INFO_SIZE != 0 {
        return Err("truncated probe records".into());
    }
    data.chunks_exact(INFO_SIZE).map(info).collect()
}
fn decode_batch(data: &[u8]) -> Result<Json, String> {
    if data.len() < BATCH_SIZE {
        return Err("truncated probe batch".into());
    }
    let count = rd32(data, 104) as usize;
    let more = rd32(data, 108);
    if count > READ_MAX as usize || more > 1 || data.len() != BATCH_SIZE + count * EVENT_SIZE {
        return Err("invalid probe batch length/flags".into());
    }
    let mut previous = 0;
    let mut events = Vec::with_capacity(count);
    for event in data[BATCH_SIZE..].chunks_exact(EVENT_SIZE) {
        let seq = rd64(event, 0);
        if seq <= previous || seq > rd64(data, 32) {
            return Err("invalid probe event sequence".into());
        }
        previous = seq;
        events.push(Json::Obj(vec![
            ("seq".into(), Json::UInt(seq)),
            ("hit".into(), Json::UInt(rd64(event, 8))),
            ("ts_ns".into(), Json::UInt(rd64(event, 16))),
            ("tid".into(), Json::UInt(rd32(event, 24) as u64)),
            ("clock_failed".into(), Json::Bool(rd32(event, 28) & 1 != 0)),
            ("pc".into(), Json::hex(rd64(event, 32))),
            ("sp".into(), Json::hex(rd64(event, 40))),
            ("nzcv".into(), Json::hex(rd64(event, 48))),
            (
                "regs".into(),
                Json::Obj(
                    (0..31)
                        .map(|i| (format!("x{i}"), Json::hex(rd64(event, 56 + i * 8))))
                        .collect(),
                ),
            ),
        ]));
    }
    let next = rd64(data, 88);
    if next > rd64(data, 32) || (count > 0 && next != previous) {
        return Err("invalid probe batch cursor".into());
    }
    Ok(Json::Obj(vec![
        ("probe".into(), info(&data[..INFO_SIZE])?),
        ("next_seq".into(), Json::UInt(next)),
        ("lost".into(), Json::UInt(rd64(data, 96))),
        ("more".into(), Json::Bool(more != 0)),
        ("events".into(), Json::Arr(events)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(text: &str) -> Result<Command, String> {
        Command::parse(
            &format!("ij2art ctl --pid 1 {text}")
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )
    }
    #[test]
    fn rejects_ambiguous_or_malformed_probes() {
        for text in [
            "probe add",
            "probe add --offset 4",
            "probe add --in lib.so",
            "probe add --target fn",
            "probe add --target 0x0",
            "probe add --target 0x100 --in lib.so",
            "probe add --target 0x100 --when x31=1",
            "probe add --target 0x100 --when x0=1=2",
            "probe add --target 0x100 --offset 3",
            "probe add --target 0x100 --tid 2147483648",
            "probe add --target 0x100 --max-hits -1",
            "probe add --target 0x100 --target 0x200",
            "probe add --target",
            "probe add --target 0x100 --typo 4",
            "probe query 0",
            "probe read 1 --limit 0",
            "probe read 1 --limit 49",
            "probe read 1 --after -1",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert_eq!(condition("x30=0xffffffffffffffff").unwrap(), (30, u64::MAX));
    }
    #[test]
    fn accepts_each_addressing_mode_and_filter() {
        for text in [
            "probe list",
            "probe del 1",
            "probe query 1",
            "probe read 1 --after 12 --limit 2",
            "probe add --target 0x100 --tid 2 --max-hits 4 --when x0=3",
            "probe add --target func --in lib.so --offset 0x4",
            "probe add --in lib.so --offset 0x1000",
        ] {
            assert!(parse(text).is_ok(), "{text}");
        }
    }
    #[test]
    fn checks_wire_boundaries_and_cursors() {
        assert!(decode(&[0; INFO_SIZE - 1]).is_err());
        assert!(decode(&[0; INFO_SIZE]).is_err());
        let mut wire = vec![0; BATCH_SIZE + EVENT_SIZE];
        wr32(&mut wire, 72, 4);
        wr32(&mut wire, 68, NO_CONDITION);
        wr64(&mut wire, 32, 7);
        wr64(&mut wire, 88, 7);
        wr32(&mut wire, 104, 1);
        wr64(&mut wire, BATCH_SIZE, 7);
        wr64(&mut wire, BATCH_SIZE + 56 + 30 * 8, 0xffff1234);
        let decoded = decode_batch(&wire).unwrap().to_string();
        assert!(decoded.contains("\"state\":\"LIMITED\""));
        assert!(decoded.contains("\"x30\":\"0xffff1234\""));
        assert!(decode_batch(&wire[..wire.len() - 1]).is_err());
        wr64(&mut wire, 88, 6);
        assert!(decode_batch(&wire).is_err());
        wr64(&mut wire, 88, 7);
        wr32(&mut wire, 104, 49);
        assert!(decode_batch(&wire).is_err());
    }
}
