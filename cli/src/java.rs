//! JSON method-call jobs. The Android strict JSON parser validates the schema.
use crate::art::request;
use crate::ctl::{Outcome, Ring};
use crate::json::Json;
use crate::proto;
use std::io::Read;

const CALL: u32 = 60;
const QUERY: u32 = 61;
pub(crate) const LIST: u32 = 62;
const DROP: u32 = 63;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Call {
        dex_id: u64,
        main: bool,
        json: Vec<u8>,
    },
    Query(u64),
    List,
    Drop(u64),
}

fn id(text: &str) -> Result<u64, String> {
    let value = if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse()
    }
    .map_err(|_| "invalid Java job_id/dex_id".to_string())?;
    if value == 0 {
        return Err("job_id/dex_id must be nonzero".into());
    }
    Ok(value)
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
            ["java", "query", key] => Ok(Self::Query(id(key)?)),
            ["java", "del", key] => Ok(Self::Drop(id(key)?)),
            ["java", "list"] => Ok(Self::List),
            ["java", "call", rest @ ..] => {
                if rest.len() % 2 != 0 { return Err("Java options require values (see help java)".into()); }
                let (mut dex_id, mut main, mut input) = (None, None, None);
                for pair in rest.chunks_exact(2) {
                    match pair[0] {
                        "--dex-id" if dex_id.is_none() => dex_id = Some(id(pair[1])?),
                        "--thread" if main.is_none() => main = Some(match pair[1] {
                            "main" => true,
                            "new" => false,
                            _ => return Err("--thread must be main or new".into()),
                        }),
                        "--request" if input.is_none() => input = Some(pair[1].as_bytes().to_vec()),
                        "--file" if input.is_none() => {
                            let mut bytes = Vec::new();
                            std::fs::File::open(pair[1]).map_err(|e| format!("{}: {e}", pair[1]))?
                                .take(proto::CMD_DATA_MAX as u64 + 1)
                                .read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                            input = Some(bytes);
                        }
                        other => return Err(format!("unknown/duplicate java call option: {other}")),
                    }
                }
                let json = input.ok_or("java call requires --request JSON or --file PATH (see help java)")?;
                if json.is_empty() || json.len() > proto::CMD_DATA_MAX || json.contains(&0) {
                    return Err("Java request must contain 1..3992 UTF-8 bytes, without raw NUL".into());
                }
                std::str::from_utf8(&json).map_err(|_| "Java request must be UTF-8")?;
                Ok(Self::Call {
                    dex_id: dex_id.unwrap_or(0),
                    main: main.ok_or("java call requires explicit --thread main|new")?,
                    json,
                })
            }
            _ => Err("usage: java call --thread main|new [--dex-id ID] --request JSON | java query/list/del (see help java)".into()),
        }
    }

    pub fn run(self, ring: &mut Ring) -> Result<Outcome, String> {
        let response = match self {
            Self::Call { dex_id, main, json } => request(ring, CALL, dex_id, main as u64, &json)?,
            Self::Query(id) => request(ring, QUERY, id, 0, &[])?,
            Self::Drop(id) => request(ring, DROP, id, 0, &[])?,
            Self::List => request(ring, LIST, 0, 0, &[])?,
        };
        let text = String::from_utf8(response.data).map_err(|_| "invalid Java response UTF-8")?;
        Ok(Outcome::new(format!("{text}\n"), Json::Raw(text)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(words: &[&str]) -> Result<Command, String> {
        let mut args: Vec<String> = ["ij2art", "ctl", "--pid", "123"]
            .map(String::from)
            .to_vec();
        args.extend(words.iter().map(|s| s.to_string()));
        Command::parse(&args)
    }
    #[test]
    fn explicit_thread_and_single_input() {
        let json = r#"{"calls":[{"class":"a.B","method":"f"}]}"#;
        assert_eq!(
            parse(&[
                "java",
                "call",
                "--request",
                json,
                "--thread",
                "main",
                "--dex-id",
                "0xffffffffffffffff"
            ])
            .unwrap(),
            Command::Call {
                dex_id: u64::MAX,
                main: true,
                json: json.as_bytes().to_vec()
            }
        );
        for words in [
            vec!["java", "call", "--request", json],
            vec!["java", "call", "--request", json, "--thread", "worker"],
            vec![
                "java",
                "call",
                "--request",
                json,
                "--request",
                json,
                "--thread",
                "new",
            ],
            vec!["java", "query", "0"],
            vec!["java", "list", "extra"],
        ] {
            assert!(parse(&words).is_err(), "{words:?}");
        }
    }
    #[test]
    fn bounded_request_and_unicode() {
        assert!(parse(&[
            "java",
            "call",
            "--thread",
            "new",
            "--request",
            &"x".repeat(3993)
        ])
        .is_err());
        assert!(parse(&["java", "call", "--thread", "new", "--request", "\0"]).is_err());
        assert!(parse(&[
            "java",
            "call",
            "--thread",
            "new",
            "--request",
            "{\"calls\":[],\"caf\u{e9}\":\"na\u{ef}ve\"}"
        ])
        .is_ok());
        assert_eq!(parse(&["java", "query", "42"]).unwrap(), Command::Query(42));
    }
}
