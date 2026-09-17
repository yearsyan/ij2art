//! Separate DEX-object and Hook APIs over the existing single-request control ring.
use crate::ctl::{check_status, rd32, rd64, wr32, wr64, Outcome, Ring};
use crate::json::Json;
use crate::proto;
use std::io::Read;

pub const DEX_BEGIN: u32 = 20;
pub const DEX_CHUNK: u32 = 21;
pub const DEX_COMMIT: u32 = 22;
pub const DEX_QUERY: u32 = 23;
pub const DEX_DROP: u32 = 24;
pub const DEX_LIST: u32 = 25;
pub const HOOK_INIT: u32 = 30;
pub const HOOK_ADD: u32 = 31;
pub const HOOK_DEL: u32 = 32;
pub const HOOK_LIST: u32 = 33;
pub const HOOK_QUERY: u32 = 34;
pub const HOOK_UPDATE: u32 = 35;
/// The IJ2ART_COVERAGE_ENTRY value from common/art_proto.h. A hook can only ever intercept
/// calls that are dispatched through the entry of the target method (a caller's inlined
/// copy bypasses it), so the protocol always requests ENTRY.
pub const COVERAGE_ENTRY: u64 = 2;
pub const DEX_MAX: usize = 8 * 1024 * 1024;
pub const DEX_INFO_SIZE: usize = 48;

/// Generic observation replacement embedded by build.sh (`tracer.dex`). It is never
/// injected on its own: the bytes enter an app only through `dex upload --builtin tracer`
/// or the `hook trace` convenience command. Host-test builds carry an empty stub.
pub static TRACER_DEX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tracer.dex"));
/// The tracer's replacement selector, already matching the published HookContext contract.
pub const TRACER_REPLACEMENT: &str =
    "org.ij2art.tracer.Tracer.trace(Lorg/ij2art/HookContext;)Ljava/lang/Object;";
/// Logcat tag the tracer writes entry/exit records to.
pub const TRACER_LOGCAT_TAG: &str = "ij2art.trace";
/// Fixed upload nonce: every `--builtin tracer` upload is idempotent, because a repeated
/// DEX_BEGIN with the same nonce and size returns the READY entry created earlier.
pub const TRACER_NONCE: u64 = u64::from_le_bytes(*b"ij2trace");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexInfo {
    pub id: u64,
    pub nonce: u64,
    pub size: u64,
    pub received: u64,
    pub state: u32,
    pub hook_refs: u32,
    pub error: i32,
}
impl DexInfo {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != DEX_INFO_SIZE {
            return Err("invalid DEX response length".into());
        }
        let value = Self {
            id: rd64(bytes, 0),
            nonce: rd64(bytes, 8),
            size: rd64(bytes, 16),
            received: rd64(bytes, 24),
            state: rd32(bytes, 32),
            hook_refs: rd32(bytes, 36),
            error: rd32(bytes, 40) as i32,
        };
        if value.id == 0
            || value.nonce == 0
            || value.size > DEX_MAX as u64
            || value.received > value.size
            || !(1..=3).contains(&value.state)
        {
            return Err("invalid DEX response fields".into());
        }
        Ok(value)
    }
    fn state_name(&self) -> &'static str {
        match self.state {
            1 => "UPLOADING",
            2 => "READY",
            _ => "FAILED",
        }
    }
}
/// The JSON shape of a record, shared by overview and dex list.
pub(crate) fn dex_json(bytes: &[u8]) -> Result<Json, String> {
    Ok(dex_info_json(&DexInfo::decode(bytes)?))
}
fn dex_info_json(info: &DexInfo) -> Json {
    Json::Obj(vec![
        ("id".into(), Json::UInt(info.id)),
        ("nonce".into(), Json::UInt(info.nonce)),
        ("size".into(), Json::UInt(info.size)),
        ("received".into(), Json::UInt(info.received)),
        ("state".into(), Json::text(info.state_name())),
        ("hook_refs".into(), Json::UInt(info.hook_refs as u64)),
        ("error".into(), Json::Int(info.error as i64)),
    ])
}

pub fn request(
    ring: &mut Ring,
    kind: u32,
    id: u64,
    arg: u64,
    data: &[u8],
) -> Result<crate::ctl::Response, String> {
    if data.len() > proto::CMD_DATA_MAX {
        return Err("ART request exceeds command slot".into());
    }
    let response = ring.rpc(|c| {
        wr32(c, proto::C_TYPE, kind);
        wr64(c, proto::C_ADDR, id);
        wr64(c, proto::C_ARGS, arg);
        wr64(c, proto::C_LEN, data.len() as u64);
        c[proto::C_DATA..proto::C_DATA + data.len()].copy_from_slice(data);
    })?;
    check_status(&response)?;
    Ok(response)
}

/// A request that carries an array of arguments (HOOK_INIT has none by default, and this
/// also accommodates the address array of the legacy protocol).
pub fn request_args(
    ring: &mut Ring,
    kind: u32,
    args: &[u64],
    data: &[u8],
) -> Result<crate::ctl::Response, String> {
    if args.len() > 8 {
        return Err("too many arguments".into());
    }
    if data.len() > proto::CMD_DATA_MAX {
        return Err("ART request exceeds command slot".into());
    }
    let response = ring.rpc(|c| {
        wr32(c, proto::C_TYPE, kind);
        wr32(c, proto::C_ARGSN, args.len() as u32);
        for (i, v) in args.iter().enumerate() {
            wr64(c, proto::C_ARGS + i * 8, *v);
        }
        wr64(c, proto::C_LEN, data.len() as u64);
        c[proto::C_DATA..proto::C_DATA + data.len()].copy_from_slice(data);
    })?;
    check_status(&response)?;
    Ok(response)
}

pub struct HookInfo {
    pub id: u64,
    pub hits: u64,
    pub last_hit_ms: u64,
    pub state: u32,
    pub in_flight: u32,
    pub coverage: u32,
    pub generation: u32,
    pub target: String,
    pub replacement: String,
}

pub const HOOK_INFO_HEADER: usize = 48;

fn decode_hook(bytes: &[u8]) -> Result<(HookInfo, usize), String> {
    if bytes.len() < HOOK_INFO_HEADER {
        return Err("short hook record".into());
    }
    let target_len = u16::from_le_bytes([bytes[32], bytes[33]]) as usize;
    let replacement_len = u16::from_le_bytes([bytes[34], bytes[35]]) as usize;
    let total = HOOK_INFO_HEADER + target_len + replacement_len;
    if bytes.len() < total {
        return Err("short hook record strings".into());
    }
    Ok((
        HookInfo {
            id: rd64(bytes, 0),
            hits: rd64(bytes, 8),
            last_hit_ms: rd64(bytes, 16),
            state: rd32(bytes, 24),
            in_flight: rd32(bytes, 28),
            coverage: rd32(bytes, 40),
            generation: rd32(bytes, 44),
            target: String::from_utf8_lossy(&bytes[48..48 + target_len]).into_owned(),
            replacement: String::from_utf8_lossy(&bytes[48 + target_len..total]).into_owned(),
        },
        total,
    ))
}

fn hook_state_name(state: u32) -> &'static str {
    match state {
        2 => "ACTIVE",
        3 => "DRAINING",
        4 => "DISABLED",
        _ => "UNKNOWN",
    }
}
fn hook_coverage_name(coverage: u32) -> &'static str {
    match coverage {
        1 => "FULL",
        2 => "ENTRY_ONLY",
        _ => "UNKNOWN",
    }
}
fn hook_json(info: &HookInfo) -> Json {
    Json::Obj(vec![
        ("id".into(), Json::UInt(info.id)),
        ("hits".into(), Json::UInt(info.hits)),
        ("last_hit_ms".into(), Json::UInt(info.last_hit_ms)),
        ("state".into(), Json::text(hook_state_name(info.state))),
        ("in_flight".into(), Json::UInt(info.in_flight as u64)),
        ("coverage".into(), Json::text(hook_coverage_name(info.coverage))),
        ("generation".into(), Json::UInt(info.generation as u64)),
        ("target".into(), Json::text(info.target.clone())),
        ("replacement".into(), Json::text(info.replacement.clone())),
    ])
}
/// The record JSON shared by overview and hook list; returns the record together with the
/// number of bytes it consumed.
pub(crate) fn decode_hook_json(bytes: &[u8]) -> Result<(Json, usize), String> {
    let (info, used) = decode_hook(bytes)?;
    Ok((hook_json(&info), used))
}
fn hook_text(info: &HookInfo) -> String {
    let mut out = format!(
        "hook_id={} state={} hits={} in_flight={} last_hit_ms={} generation={}\n",
        info.id,
        hook_state_name(info.state),
        info.hits,
        info.in_flight,
        info.last_hit_ms,
        info.generation
    );
    out.push_str(&format!(
        "  coverage    {}\n",
        match info.coverage {
            1 => "FULL",
            2 => "ENTRY_ONLY (existing inlined callers may bypass)",
            _ => "UNKNOWN",
        }
    ));
    out.push_str(&format!("  target      {}\n", info.target));
    if info.state == 3 || info.state == 4 {
        out.push_str(
            "  logical disable: JNI forwarding and DEX roots retained; physical restore unsupported\n",
        );
    }
    out.push_str(&format!("  replacement {}\n", info.replacement));
    out
}

/// Upload creates a reusable DEX object. It never installs a Hook or selects a method.
/// Keep the same nonce and bytes to resume after an uncertain timeout.
pub fn upload_dex(ring: &mut Ring, bytes: &[u8], nonce: u64) -> Result<DexInfo, String> {
    validate_dex(bytes)?;
    if nonce == 0 {
        return Err("upload nonce must be nonzero".into());
    }
    let response = ring.rpc(|c| {
        wr32(c, proto::C_TYPE, DEX_BEGIN);
        wr64(c, proto::C_ARGS, nonce);
        wr64(c, proto::C_LEN, bytes.len() as u64);
    })?;
    check_status(&response)?;
    let info = DexInfo::decode(&response.data)?;
    if info.nonce != nonce || info.size != bytes.len() as u64 {
        return Err("upload response identity/size mismatch".into());
    }
    if info.state == 3 {
        return Err(format!(
            "upload failed with {}; delete dex_id {} before retrying",
            info.error, info.id
        ));
    }
    // Replay chunks to verify content against a previous UPLOADING object. A reused nonce
    // with different data must not silently combine two files. READY cannot be overwritten.
    if info.state == 2 {
        return Ok(info);
    }
    for (n, chunk) in bytes.chunks(proto::CMD_DATA_MAX).enumerate() {
        let response = request(
            ring,
            DEX_CHUNK,
            info.id,
            (n * proto::CMD_DATA_MAX) as u64,
            chunk,
        )?;
        let updated = DexInfo::decode(&response.data)?;
        if updated.id != info.id {
            return Err("DEX chunk identity mismatch".into());
        }
    }
    commit_dex(ring, info.id)
}

pub fn commit_dex(ring: &mut Ring, id: u64) -> Result<DexInfo, String> {
    let response = request(ring, DEX_COMMIT, id, 0, &[])?;
    let value = DexInfo::decode(&response.data)?;
    if value.id != id || value.state != 2 {
        return Err("DEX commit did not return a loaded dex_id".into());
    }
    Ok(value)
}

/// Idempotent upload of the embedded tracer DEX under its fixed nonce.
fn upload_tracer(ring: &mut Ring) -> Result<DexInfo, String> {
    if TRACER_DEX.is_empty() {
        return Err("builtin tracer dex is not embedded in this build".into());
    }
    upload_dex(ring, TRACER_DEX, TRACER_NONCE)
}

/// Full replacement requires a previously loaded dex_id and TWO explicit selectors.
pub fn install_hook(
    ring: &mut Ring,
    dex_id: u64,
    target: &str,
    replacement: &str,
) -> Result<u64, String> {
    let data = hook_payload(target, replacement)?;
    let response = request(ring, HOOK_ADD, dex_id, COVERAGE_ENTRY, &data)?;
    if response.retval == 0 {
        return Err("Hook backend did not return a hook_id".into());
    }
    Ok(response.retval)
}

fn hook_payload(target: &str, replacement: &str) -> Result<Vec<u8>, String> {
    validate_method(target)?;
    validate_replacement(replacement)?;
    let mut data = Vec::with_capacity(8 + target.len() + replacement.len());
    data.extend_from_slice(&(target.len() as u32).to_le_bytes());
    data.extend_from_slice(&(replacement.len() as u32).to_le_bytes());
    data.extend_from_slice(target.as_bytes());
    data.extend_from_slice(replacement.as_bytes());
    Ok(data)
}

fn validate_replacement(replacement: &str) -> Result<(), String> {
    validate_method(replacement)?;
    if replacement
        .split('(')
        .next()
        .is_some_and(|name| name.ends_with(".<init>"))
    {
        return Err("replacement must be a method, not a constructor".into());
    }
    Ok(())
}

fn descriptor(bytes: &[u8], cursor: &mut usize, allow_void: bool) -> Result<(), String> {
    let fail = || "invalid JVM method descriptor".to_string();
    let Some(&kind) = bytes.get(*cursor) else {
        return Err(fail());
    };
    *cursor += 1;
    match kind {
        b'V' if allow_void => Ok(()),
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => Ok(()),
        b'L' => {
            let start = *cursor;
            while bytes.get(*cursor).is_some_and(|c| *c != b';') {
                *cursor += 1;
            }
            let name = &bytes[start..*cursor];
            if bytes.get(*cursor) != Some(&b';')
                || name.is_empty()
                || name.split(|c| *c == b'/').any(|part| {
                    part.is_empty()
                        || part
                            .iter()
                            .any(|c| !c.is_ascii_alphanumeric() && !b"_$".contains(c))
                })
            {
                return Err(fail());
            }
            *cursor += 1;
            Ok(())
        }
        b'[' => {
            let mut dimensions = 1;
            while bytes.get(*cursor) == Some(&b'[') {
                dimensions += 1;
                *cursor += 1;
            }
            if dimensions > 255 {
                return Err(fail());
            }
            descriptor(bytes, cursor, false)
        }
        _ => Err(fail()),
    }
}
fn validate_method(method: &str) -> Result<(), String> {
    if method.is_empty() || method.len() > 1024 || !method.bytes().all(|b| b > 0x20 && b < 0x7f) {
        return Err("method selector must contain 1..1024 printable ASCII bytes".into());
    }
    let open = method
        .find('(')
        .ok_or("method selector needs a JVM descriptor")?;
    let name = &method[..open];
    let (owner, member) = name
        .rsplit_once('.')
        .ok_or("expected binary.class.Name.method(args)return")?;
    if member == "<clinit>" {
        return Err("class initializers are unsupported".into());
    }
    let ordinary_name = |s: &str| {
        s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
    };
    if owner.split('.').any(ordinary_name) || (member != "<init>" && ordinary_name(member)) {
        return Err("expected binary.class.Name.method(args)return".into());
    }
    let mut cursor = open + 1;
    let mut count = 0;
    while method.as_bytes().get(cursor) != Some(&b')') {
        descriptor(method.as_bytes(), &mut cursor, false)?;
        count += 1;
        if count > 255 {
            return Err("too many method parameters".into());
        }
    }
    cursor += 1;
    if member == "<init>" && &method[cursor..] != "V" {
        return Err("constructor return type must be V".into());
    }
    descriptor(method.as_bytes(), &mut cursor, true)?;
    if cursor != method.len() {
        return Err("trailing method descriptor bytes".into());
    }
    Ok(())
}
fn validate_dex(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < 112
        || bytes.len() > DEX_MAX
        || &bytes[..4] != b"dex\n"
        || bytes[7] != 0
        || ![b"035", b"037", b"038", b"039", b"040"]
            .iter()
            .any(|version| version.as_slice() == &bytes[4..7])
        || rd32(bytes, 32) as usize != bytes.len()
        || rd32(bytes, 36) != 112
        || rd32(bytes, 40) != 0x12345678
    {
        return Err(
            "expected a standalone dex 035/037-040 file, at most 8 MiB (no APK/JAR/container)"
                .into(),
        );
    }
    let (mut a, mut b) = (1u32, 0u32);
    for value in &bytes[12..] {
        a = (a + *value as u32) % 65521;
        b = (b + a) % 65521;
    }
    if rd32(bytes, 8) != (b << 16 | a) {
        return Err("DEX checksum mismatch".into());
    }
    Ok(())
}

#[derive(Debug)]
pub enum Command {
    Upload {
        path: String,
        nonce: u64,
    },
    UploadTracer,
    Commit(u64),
    Query {
        id: u64,
        nonce: u64,
    },
    Drop(u64),
    ListDex,
    Init,
    Hook {
        dex_id: u64,
        target: String,
        replacement: String,
    },
    UpdateHook {
        hook_id: u64,
        dex_id: u64,
        replacement: String,
    },
    Trace {
        target: String,
    },
    DropHook(u64),
    QueryHook(u64),
    ListHooks,
}
fn id(text: &str) -> Result<u64, String> {
    let value = if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    }
    .map_err(|_| format!("invalid id/nonce: {text}"))?;
    if value == 0 {
        return Err("id/nonce must be nonzero".into());
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
impl Command {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut words = Vec::new();
        let mut it = args.iter().skip(2);
        while let Some(word) = it.next() {
            if word == "--pid" || word == "--pkg" {
                it.next().ok_or("missing process selector value")?;
            } else {
                words.push(word.as_str());
            }
        }
        match words.as_slice() {
            ["dex", "upload", "--builtin", "tracer"] => Ok(Self::UploadTracer),
            ["dex", "upload", "--builtin", other] => {
                Err(format!("unknown builtin dex: {other} (only 'tracer')"))
            }
            ["dex", "upload", path] => Ok(Self::Upload {
                path: (*path).into(),
                nonce: nonce()?,
            }),
            ["dex", "upload", path, "--nonce", key] => Ok(Self::Upload {
                path: (*path).into(),
                nonce: id(key)?,
            }),
            ["dex", "commit", key] => Ok(Self::Commit(id(key)?)),
            ["dex", "query", key] => Ok(Self::Query {
                id: id(key)?,
                nonce: 0,
            }),
            ["dex", "query", "--nonce", key] => Ok(Self::Query {
                id: 0,
                nonce: id(key)?,
            }),
            ["dex", "del", key] => Ok(Self::Drop(id(key)?)),
            ["dex", "list"] => Ok(Self::ListDex),
            ["hook", "init"] => Ok(Self::Init),
            ["hook", "del", key] => Ok(Self::DropHook(id(key)?)),
            ["hook", "query", key] => Ok(Self::QueryHook(id(key)?)),
            ["hook", "list"] => Ok(Self::ListHooks),
            ["hook", "update", key, rest @ ..] => {
                if rest.len() != 4 {
                    return Err("hook update requires ID --dex-id ID --replacement METHOD".into());
                }
                let mut dex_id = None;
                let mut replacement = None;
                for pair in rest.chunks_exact(2) {
                    match pair[0] {
                        "--dex-id" if dex_id.is_none() => dex_id = Some(id(pair[1])?),
                        "--replacement" if replacement.is_none() => {
                            replacement = Some(pair[1].to_string())
                        }
                        "--builtin" if replacement.is_none() && pair[1] == "tracer" => {
                            replacement = Some(TRACER_REPLACEMENT.to_string())
                        }
                        "--builtin" if replacement.is_none() => {
                            return Err(format!("unknown builtin dex: {} (only 'tracer')", pair[1]))
                        }
                        _ => return Err(format!("unknown/duplicate hook update option: {}", pair[0])),
                    }
                }
                let replacement = replacement.ok_or("missing --replacement")?;
                validate_replacement(&replacement)?;
                Ok(Self::UpdateHook {
                    hook_id: id(key)?,
                    dex_id: dex_id.ok_or("missing --dex-id")?,
                    replacement,
                })
            }
            ["hook", "add", rest @ ..] => {
                let mut dex_id = None;
                let mut target = None;
                let mut replacement = None;
                if rest.len() != 6 {
                    return Err(if rest.chunks(2).any(|p| p[0] == "--coverage") {
                        "--coverage was removed: hooks only intercept entry-dispatched calls \
                         (ENTRY_ONLY) by design"
                            .into()
                    } else {
                        "hook add requires --dex-id ID --target METHOD --replacement METHOD".into()
                    });
                }
                for pair in rest.chunks_exact(2) {
                    match pair[0] {
                        "--dex-id" if dex_id.is_none() => dex_id = Some(id(pair[1])?),
                        "--target" if target.is_none() => target = Some(pair[1].to_string()),
                        "--replacement" if replacement.is_none() => {
                            replacement = Some(pair[1].to_string())
                        }
                        "--builtin" if replacement.is_none() && pair[1] == "tracer" => {
                            replacement = Some(TRACER_REPLACEMENT.to_string())
                        }
                        "--builtin" if replacement.is_none() => {
                            return Err(format!("unknown builtin dex: {} (only 'tracer')", pair[1]))
                        }
                        _ => return Err(format!("unknown/duplicate hook option: {}", pair[0])),
                    }
                }
                let target = target.ok_or("missing --target")?;
                let replacement = replacement.ok_or("missing --replacement")?;
                hook_payload(&target, &replacement)?;
                Ok(Self::Hook {
                    dex_id: dex_id.ok_or("missing --dex-id")?,
                    target,
                    replacement,
                })
            }
            ["hook", "trace", "--target", target] => {
                validate_method(target)?;
                Ok(Self::Trace {
                    target: (*target).into(),
                })
            }
            _ => Err(
                "usage: dex upload/commit/query/list/del | hook init/add/update/trace/query/list/del (see help)"
                    .into(),
            ),
        }
    }
    pub fn run(self, ring: &mut Ring) -> Result<Outcome, String> {
        match self {
            Self::UploadTracer => {
                let info = upload_tracer(ring)?;
                Ok(Outcome::new(
                    format!("{}\n", info.id),
                    Json::Obj(vec![
                        ("id".into(), Json::UInt(info.id)),
                        ("nonce".into(), Json::UInt(info.nonce)),
                        ("size".into(), Json::UInt(info.size)),
                        ("state".into(), Json::text(info.state_name())),
                        ("builtin".into(), Json::text("tracer")),
                    ]),
                ))
            }
            Self::Upload { path, nonce } => {
                let file = std::fs::File::open(&path).map_err(|e| format!("{path}: {e}"))?;
                let mut bytes = Vec::new();
                file.take(DEX_MAX as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                validate_dex(&bytes)?;
                eprintln!("upload_nonce={nonce}; timeout recovery: dex query --nonce {nonce}");
                let info = upload_dex(ring, &bytes, nonce)?;
                // The human-readable stdout stays machine-readable: it holds only the
                // loaded dex_id.
                Ok(Outcome::new(format!("{}\n", info.id), dex_info_json(&info)))
            }
            Self::Commit(id) => {
                let info = commit_dex(ring, id)?;
                Ok(Outcome::new(format!("{}\n", info.id), dex_info_json(&info)))
            }
            Self::Query { id, nonce } => {
                let info = DexInfo::decode(&request(ring, DEX_QUERY, id, nonce, &[])?.data)?;
                Ok(Outcome::new(info_text(&info), dex_info_json(&info)))
            }
            Self::Drop(id) => {
                request(ring, DEX_DROP, id, 0, &[])?;
                Ok(Outcome::new(
                    "",
                    Json::Obj(vec![("deleted".into(), Json::UInt(id))]),
                ))
            }
            Self::ListDex => {
                let response = request(ring, DEX_LIST, 0, 0, &[])?;
                if response.flags & 1 != 0 || response.data.len() % DEX_INFO_SIZE != 0 {
                    return Err("invalid/truncated DEX list".into());
                }
                let mut human = String::new();
                let mut records = Vec::new();
                for bytes in response.data.chunks_exact(DEX_INFO_SIZE) {
                    human.push_str(&info_text(&DexInfo::decode(bytes)?));
                    records.push(dex_json(bytes)?);
                }
                Ok(Outcome::new(
                    human,
                    Json::Obj(vec![
                        ("records".into(), Json::Arr(records)),
                        ("truncated".into(), Json::Bool(false)),
                    ]),
                ))
            }
            Self::Init => {
                // The in-process backend owns symbol/layout resolution, including hidden symbols.
                let response = request_args(ring, HOOK_INIT, &[], &[])?;
                let text = String::from_utf8_lossy(&response.data).into_owned();
                let data = Json::Raw(text.clone());
                Ok(Outcome::new(format!("{}\n", text.trim_end()), data))
            }
            Self::Hook {
                dex_id,
                target,
                replacement,
            } => {
                let id = install_hook(ring, dex_id, &target, &replacement)?;
                Ok(Outcome::new(
                    format!("{}\n", id),
                    Json::Obj(vec![("id".into(), Json::UInt(id))]),
                ))
            }
            Self::Trace { target } => {
                // hook init is idempotent, so trace can guarantee the adapter itself;
                // surface an unsupported ART with its reason instead of a bare "not ready".
                let init = request_args(ring, HOOK_INIT, &[], &[])?;
                let caps = String::from_utf8_lossy(&init.data);
                if caps.contains("\"replacement\":false") {
                    return Err(format!(
                        "ART replacement unsupported on this device: {}",
                        unsupported_reason(&caps)
                    ));
                }
                let dex = upload_tracer(ring)?;
                let id = install_hook(ring, dex.id, &target, TRACER_REPLACEMENT)?;
                Ok(Outcome::new(
                    format!(
                        "hook_id={} dex_id={}\n  target      {}\n  replacement {}\n  records: adb logcat -s {}:I\n",
                        id, dex.id, target, TRACER_REPLACEMENT, TRACER_LOGCAT_TAG
                    ),
                    Json::Obj(vec![
                        ("id".into(), Json::UInt(id)),
                        ("dex_id".into(), Json::UInt(dex.id)),
                        ("target".into(), Json::text(target.clone())),
                        ("replacement".into(), Json::text(TRACER_REPLACEMENT)),
                        ("logcat".into(), Json::text(TRACER_LOGCAT_TAG)),
                    ]),
                ))
            }
            Self::DropHook(id) => {
                let r = request(ring, HOOK_DEL, id, 0, &[])?;
                let (info, _) = decode_hook(&r.data)?;
                Ok(Outcome::new(hook_text(&info), hook_json(&info)))
            }
            Self::UpdateHook {
                hook_id,
                dex_id,
                replacement,
            } => {
                let r = request(ring, HOOK_UPDATE, hook_id, dex_id, replacement.as_bytes())?;
                let (info, used) = decode_hook(&r.data)?;
                if used != r.data.len() || info.id != hook_id || r.retval != hook_id {
                    return Err("invalid Hook update response".into());
                }
                Ok(Outcome::new(hook_text(&info), hook_json(&info)))
            }
            Self::QueryHook(id) => {
                let r = request(ring, HOOK_QUERY, id, 0, &[])?;
                let (info, _) = decode_hook(&r.data)?;
                Ok(Outcome::new(hook_text(&info), hook_json(&info)))
            }
            Self::ListHooks => {
                let r = request(ring, HOOK_LIST, 0, 0, &[])?;
                let mut human = String::new();
                let mut records = Vec::new();
                let mut at = 0;
                while at < r.data.len() {
                    let (info, used) = decode_hook(&r.data[at..])?;
                    human.push_str(&hook_text(&info));
                    records.push(hook_json(&info));
                    at += used;
                }
                let truncated = r.flags & 1 != 0;
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
fn info_text(info: &DexInfo) -> String {
    format!(
        "dex_id={} nonce={} state={} received={}/{} hook_refs={} error={}\n",
        info.id,
        info.nonce,
        info.state_name(),
        info.received,
        info.size,
        info.hook_refs,
        info.error
    )
}

/// Pulls "unsupported_reason" out of the hook-init capability JSON (which the payload
/// emits with only quote/backslash escaping); falls back to the trimmed payload.
fn unsupported_reason(caps: &str) -> String {
    const KEY: &str = "\"unsupported_reason\":\"";
    if let Some(start) = caps.find(KEY) {
        let rest = &caps[start + KEY.len()..];
        let mut reason = String::new();
        let mut escaped = false;
        for ch in rest.chars() {
            match (escaped, ch) {
                (true, c) => {
                    reason.push(c);
                    escaped = false;
                }
                (false, '\\') => escaped = true,
                (false, '"') => {
                    if !reason.is_empty() {
                        return reason;
                    }
                    break;
                }
                (false, c) => reason.push(c),
            }
        }
    }
    caps.trim().chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_descriptors_before_request() {
        for valid in [
            "a.Foo.f(I)I",
            "a.Foo.f([Ljava/lang/String;[[I)Ljava/lang/Object;",
            "a.Foo.f()V",
            "a.Foo.<init>()V",
            "a.Foo$Inner.<init>(ILjava/lang/String;)V",
        ] {
            validate_method(valid).unwrap();
        }
        for invalid in [
            "a.Foo.f(V)I",
            "a.Foo.f([V)V",
            "a.Foo.f(L;)V",
            "a.Foo.f()II",
            "a.Foo.f(I",
            "a.Foo.f(Ljava.lang.String;)V",
            "a.Foo.<init>()I",
            "a.Foo.<clinit>()V",
            "a.Foo.<other>()V",
            "a.<init>.f()V",
        ] {
            assert!(validate_method(invalid).is_err(), "{invalid}");
        }
    }
    #[test]
    fn hook_requires_uploaded_id_and_both_methods() {
        let parse =
            |s: &str| Command::parse(&s.split_whitespace().map(str::to_string).collect::<Vec<_>>());
        assert!(matches!(parse("ij2art ctl --pid 12 hook add --target a.Foo.f(I)I --dex-id 123 --replacement a.R.f(Lorg/ij2art/HookContext;)Ljava/lang/Object;").unwrap(), Command::Hook { dex_id: 123, .. }));
        assert!(matches!(parse("ij2art ctl --pid 12 hook add --target a.Foo.<init>(I)V --dex-id 123 --replacement a.R.f(Lorg/ij2art/HookContext;)Ljava/lang/Object;").unwrap(), Command::Hook { dex_id: 123, .. }));
        assert!(hook_payload("a.Foo.<init>()V", "a.R.<init>()V").is_err());
        assert!(
            parse("ij2art ctl --pid 12 hook add --dex ./r.dex --target a.Foo.f(I)I").is_err()
        );
        assert!(parse(
            "ij2art ctl --pid 12 hook add --dex-id 123 --target a.Foo.f(I)I --target a.R.f()V"
        )
        .is_err());
    }
    #[test]
    fn update_requires_hook_and_dex_without_changing_target() {
        let parse =
            |s: &str| Command::parse(&s.split_whitespace().map(str::to_string).collect::<Vec<_>>());
        assert!(matches!(parse("ij2art ctl --pid 12 hook update 42 --replacement a.R.f(Lorg/ij2art/HookContext;)Ljava/lang/Object; --dex-id 99").unwrap(),
            Command::UpdateHook { hook_id: 42, dex_id: 99, .. }));
        for invalid in [
            "hook update 0 --dex-id 99 --replacement a.R.f()V",
            "hook update 42 --dex-id 0 --replacement a.R.f()V",
            "hook update 42 --dex-id 99 --replacement a.R.<init>()V",
            "hook update 42 --dex-id 99 --dex-id 100",
            "hook update 42 --dex-id 99 --replacement a.R.f()V --target a.T.f()V",
            "hook update 42 --replacement a.R.f()V",
        ] {
            assert!(
                parse(&format!("ij2art ctl --pid 12 {invalid}")).is_err(),
                "{invalid}"
            );
        }
    }
    #[test]
    fn hook_generation_reuses_header_padding() {
        let mut bytes = vec![0; HOOK_INFO_HEADER];
        wr64(&mut bytes, 0, 42);
        wr32(&mut bytes, 44, 123);
        let (hook, size) = decode_hook(&bytes).unwrap();
        assert_eq!((hook.id, hook.generation, size), (42, 123, 48));
    }
    #[test]
    fn coverage_option_is_removed() {
        let parse =
            |s: &str| Command::parse(&s.split_whitespace().map(str::to_string).collect::<Vec<_>>());
        let base = "ij2art ctl --pid 12 hook add --dex-id 1 --target a.F.f()I --replacement a.R.f(Lorg/ij2art/HookContext;)Ljava/lang/Object;";
        assert!(matches!(
            parse(base).unwrap(),
            Command::Hook { dex_id: 1, .. }
        ));
        for gone in [
            " --coverage ENTRY_ONLY",
            " --coverage FULL",
            " --coverage AUTO",
        ] {
            let err = parse(&(base.to_owned() + gone)).unwrap_err();
            assert!(err.contains("--coverage was removed"), "{err}");
        }
    }
    #[test]
    fn method_payload_keeps_two_distinct_selectors() {
        let a = "a.Foo.f(I)I";
        let b = "a.R.f(Lorg/ij2art/HookContext;)Ljava/lang/Object;";
        let p = hook_payload(a, b).unwrap();
        assert_eq!(rd32(&p, 0) as usize, a.len());
        assert_eq!(rd32(&p, 4) as usize, b.len());
        assert_eq!(&p[8..8 + a.len()], a.as_bytes());
        assert_eq!(&p[8 + a.len()..], b.as_bytes());
    }
    #[test]
    fn builtin_tracer_parse_paths() {
        let parse =
            |s: &str| Command::parse(&s.split_whitespace().map(str::to_string).collect::<Vec<_>>());
        assert!(matches!(
            parse("ij2art ctl --pid 1 dex upload --builtin tracer").unwrap(),
            Command::UploadTracer
        ));
        assert!(parse("ij2art ctl --pid 1 dex upload --builtin other").is_err());
        assert!(matches!(
            parse("ij2art ctl --pid 1 hook add --dex-id 7 --target a.F.f(I)I --builtin tracer")
                .unwrap(),
            Command::Hook {
                dex_id: 7,
                ref replacement,
                ..
            } if replacement == TRACER_REPLACEMENT
        ));
        assert!(matches!(
            parse("ij2art ctl --pid 1 hook update 9 --dex-id 7 --builtin tracer").unwrap(),
            Command::UpdateHook {
                hook_id: 9,
                dex_id: 7,
                ..
            }
        ));
        assert!(matches!(
            parse("ij2art ctl --pid 1 hook trace --target a.F.f(I)I").unwrap(),
            Command::Trace { .. }
        ));
        // --builtin never combines with --replacement, an unknown name or a bad target.
        assert!(parse("ij2art ctl --pid 1 hook update 9 --dex-id 7 --replacement a.R.f(Lorg/ij2art/HookContext;)Ljava/lang/Object; --builtin tracer").is_err());
        assert!(parse("ij2art ctl --pid 1 hook update 9 --dex-id 7 --builtin other").is_err());
        assert!(parse("ij2art ctl --pid 1 hook add --dex-id 7 --target a.F.f()V --builtin other").is_err());
        assert!(parse("ij2art ctl --pid 1 hook trace --target no-descriptor").is_err());
        // The published constants keep the documented contract.
        assert!(validate_replacement(TRACER_REPLACEMENT).is_ok());
        assert_ne!(TRACER_NONCE, 0);
    }
    #[test]
    fn unsupported_reason_extraction() {
        let caps = "{\"replacement\":false,\"unsupported_reason\":\"no \\\"locked-code\\\" backend\"}";
        assert_eq!(
            unsupported_reason(caps),
            "no \"locked-code\" backend"
        );
        assert_eq!(unsupported_reason("{}"), "{}");
        assert!(unsupported_reason(&"x".repeat(1000)).len() <= 300);
    }
}
