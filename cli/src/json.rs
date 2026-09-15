//! A minimal JSON writer for `--json` and batch output that pulls in no external
//! dependencies.
//! The human-readable output of several ctl actions is exactly the compact form of this
//! JSON, so the field order and the formatting are kept stable.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Str(String),
    /// Ready-made JSON produced by the payload (for example inline init or hook init),
    /// which is embedded exactly as it is
    Raw(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn hex(v: u64) -> Json {
        Json::Str(format!("{:#x}", v))
    }
    pub fn text(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }
    fn render(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::UInt(n) => out.push_str(&n.to_string()),
            Json::Raw(s) => out.push_str(if s.trim().is_empty() { "null" } else { s.trim() }),
            Json::Str(s) => render_str(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.render(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    render_str(k, out);
                    out.push(':');
                    v.render(out);
                }
                out.push('}');
            }
        }
    }
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.render(&mut out);
        out
    }
}

fn render_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The success envelope: {"ok":true,"data":...}
pub fn ok(data: Json) -> String {
    Json::Obj(vec![("ok".into(), Json::Bool(true)), ("data".into(), data)]).to_string()
}
/// The error envelope: {"ok":false,"error":{"code":..or null,"message":".."}}
pub fn err(code: Option<i32>, message: &str) -> String {
    let code = code.map(|c| Json::Int(c as i64)).unwrap_or(Json::Null);
    Json::Obj(vec![
        ("ok".into(), Json::Bool(false)),
        (
            "error".into(),
            Json::Obj(vec![
                ("code".into(), code),
                ("message".into(), Json::text(message)),
            ]),
        ),
    ])
    .to_string()
}

/// The batch input format: one flat JSON array of strings per line, holding the argv for
/// that line and not including ctl itself.
/// Only string elements are accepted, with the standard escapes (including \uXXXX). This
/// covers exactly what is needed to express command-line words.
pub fn parse_argv_line(line: &str) -> Result<Vec<String>, String> {
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    let ws = |i: &mut usize| {
        while *i < bytes.len() && bytes[*i].is_whitespace() {
            *i += 1;
        }
    };
    let fail = |msg: &str| format!("batch line format error: {msg}");
    ws(&mut i);
    if bytes.get(i) != Some(&'[') {
        return Err(fail("expected a string array starting with '['"));
    }
    i += 1;
    let mut out = Vec::new();
    ws(&mut i);
    if bytes.get(i) == Some(&']') {
        i += 1; // an empty array
    } else {
        loop {
            ws(&mut i);
            if bytes.get(i) != Some(&'"') {
                return Err(fail("only string elements are accepted (after commas too)"));
            }
            i += 1;
            let mut word = String::new();
            loop {
                match bytes.get(i) {
                    None => return Err(fail("unterminated string")),
                    Some(&'"') => {
                        i += 1;
                        break;
                    }
                    Some(&'\\') => {
                        i += 1;
                        match bytes.get(i) {
                            Some('"') => word.push('"'),
                            Some('\\') => word.push('\\'),
                            Some('/') => word.push('/'),
                            Some('n') => word.push('\n'),
                            Some('r') => word.push('\r'),
                            Some('t') => word.push('\t'),
                            Some('b') => word.push('\u{0008}'),
                            Some('f') => word.push('\u{000C}'),
                            Some('u') => {
                                let hex: String =
                                    bytes.get(i + 1..i + 5).unwrap_or(&[]).iter().collect();
                                let cp = u32::from_str_radix(&hex, 16)
                                    .ok()
                                    .filter(|_| hex.len() == 4)
                                    .ok_or_else(|| fail("invalid \\u escape"))?;
                                word.push(char::from_u32(cp).ok_or_else(|| fail("invalid \\u code point"))?);
                                i += 4;
                            }
                            _ => return Err(fail("unknown escape")),
                        }
                        i += 1;
                    }
                    Some(&c) => {
                        word.push(c);
                        i += 1;
                    }
                }
            }
            out.push(word);
            ws(&mut i);
            match bytes.get(i) {
                Some(&',') => i += 1,
                Some(&']') => {
                    i += 1;
                    break;
                }
                _ => return Err(fail("expected ',' or ']' between elements")),
            }
        }
    }
    ws(&mut i);
    if i != bytes.len() {
        return Err(fail("trailing content after array"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renders_stable_shapes() {
        let v = Json::Obj(vec![
            ("id".into(), Json::UInt(7)),
            ("addr".into(), Json::hex(0x1234)),
            ("ok".into(), Json::Bool(true)),
            ("none".into(), Json::Null),
            ("list".into(), Json::Arr(vec![Json::Int(-3), Json::text("x")])) ,
        ]);
        assert_eq!(
            v.to_string(),
            "{\"id\":7,\"addr\":\"0x1234\",\"ok\":true,\"none\":null,\"list\":[-3,\"x\"]}"
        );
    }
    #[test]
    fn escapes_strings() {
        assert_eq!(Json::text("a\"b\\c\nd\u{0007}e").to_string(), "\"a\\\"b\\\\c\\nd\\u0007e\"");
        assert_eq!(Json::text("caf\u{e9}").to_string(), "\"caf\u{e9}\"");
        assert_eq!(err(Some(-44), "payload status=-44: nope"),
                   "{\"ok\":false,\"error\":{\"code\":-44,\"message\":\"payload status=-44: nope\"}}");
        assert!(err(None, "x").contains("\"code\":null"));
    }
    #[test]
    fn parses_batch_lines() {
        assert_eq!(parse_argv_line(" [\"ping\"] ").unwrap(), vec!["ping"]);
        assert_eq!(
            parse_argv_line("[\"call\",\"--in\",\"/lib c.so\",\"get\\u005fpid\"]").unwrap(),
            vec!["call", "--in", "/lib c.so", "get_pid"]
        );
        assert_eq!(parse_argv_line("[]").unwrap(), Vec::<String>::new());
        assert_eq!(parse_argv_line("[\"a\\nb\"]").unwrap(), vec!["a\nb"]);
        for bad in [
            "[1]",
            "[[\"a\"]]",
            "[\"a\",]",
            "[\"a\"",
            "\"a\"",
            "[\"a\"] extra",
            "[\"a\\q\"]",
            "",
        ] {
            assert!(parse_argv_line(bad).is_err(), "{bad}");
        }
    }
}
