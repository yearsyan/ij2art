//! The default carrier is immutable CLI data; an explicit override is read once.
//! Symbol lookup, build identity checks and injection all use those same bytes.
use std::borrow::Cow;

static EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/carrier.so"));

pub fn load(args: &[String]) -> Result<Cow<'static, [u8]>, String> {
    load_with(args, EMBEDDED)
}

fn load_with<'a>(args: &[String], embedded: &'a [u8]) -> Result<Cow<'a, [u8]>, String> {
    let bytes = if let Some(index) = args.iter().position(|arg| arg == "--carrier") {
        let path = args
            .get(index + 1)
            .filter(|path| !path.is_empty() && !path.starts_with("--"))
            .ok_or("--carrier requires a file path")?;
        Cow::Owned(std::fs::read(path).map_err(|e| format!("failed to read carrier {path}: {e}"))?)
    } else if embedded.is_empty() {
        return Err("carrier not embedded; run ./build.sh or provide --carrier PATH".into());
    } else {
        Cow::Borrowed(embedded)
    };
    // Reject bad local input before inspecting or stopping a target process.
    if bytes.len() < 64 || &bytes[..6] != b"\x7fELF\x02\x01" || bytes[16..20] != [3, 0, 183, 0] {
        return Err("carrier must be an Android arm64 ELF shared library".into());
    }
    for symbol in ["g_state", "ij2art_setup", "ij2art_unhook"] {
        if crate::elf::sym_vaddr_bytes(&bytes, symbol).is_none() {
            return Err(format!("carrier has no {symbol} symbol"));
        }
    }
    if crate::elf::build_id(&bytes).is_none() {
        return Err("carrier is missing the GNU build-id; rebuild it".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A small ELF with a GNU note and the three exported carrier symbols. It
    // keeps host tests independent of an Android toolchain or prebuilt files.
    fn fixture(id: u8) -> Vec<u8> {
        let mut b = vec![0; 576];
        b[..6].copy_from_slice(b"\x7fELF\x02\x01");
        b[16..20].copy_from_slice(&[3, 0, 183, 0]);
        for (off, value) in [
            (0x20, 64u64),
            (0x28, 128),
            (72, 320),
            (80, 320),
            (96, 24),
            (216, 384),
            (224, 96),
            (280, 480),
        ] {
            b[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (off, value) in [(0x36, 56u16), (0x38, 1), (0x3a, 64), (0x3c, 3)] {
            b[off..off + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (off, value) in [
            (64, 4u32),
            (196, 2),
            (232, 2),
            (260, 3),
            (320, 4),
            (324, 8),
            (328, 3),
        ] {
            b[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        b[332..336].copy_from_slice(b"GNU\0");
        b[336..344].fill(id);
        let mut string = 1;
        for (index, name) in ["g_state", "ij2art_setup", "ij2art_unhook"]
            .iter()
            .enumerate()
        {
            let symbol = 384 + (index + 1) * 24;
            b[symbol..symbol + 4].copy_from_slice(&(string as u32).to_le_bytes());
            b[symbol + 6] = 1;
            b[symbol + 8..symbol + 16]
                .copy_from_slice(&(0x1000u64 + index as u64 * 16).to_le_bytes());
            b[480 + string..480 + string + name.len()].copy_from_slice(name.as_bytes());
            string += name.len() + 1;
        }
        b
    }

    struct Temporary(std::path::PathBuf);
    impl Temporary {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("ij2art-carrier-{}-{stamp}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn embedded_and_override_remain_usable_without_a_carrier_file() {
        let embedded = fixture(1);
        let default = load_with(&[], &embedded).unwrap();
        assert_eq!(crate::elf::build_id(&default), Some((336, vec![1; 8])));
        assert_eq!(
            crate::elf::sym_vaddr_bytes(&default, "ij2art_unhook"),
            Some(0x1020)
        );
        let dir = Temporary::new();
        let path = dir.0.join("custom.so");
        std::fs::write(&path, fixture(2)).unwrap();
        let args = vec!["--carrier".into(), path.to_str().unwrap().into()];
        let selected = load_with(&args, &embedded).unwrap();
        assert_eq!(crate::elf::sym_vaddr(&path, "ij2art_setup"), Some(0x1010));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(crate::elf::build_id(&selected), Some((336, vec![2; 8])));
        assert_eq!(
            crate::elf::sym_vaddr_bytes(&selected, "g_state"),
            Some(0x1000)
        );
    }

    #[test]
    fn missing_or_invalid_overrides_do_not_fall_back() {
        let embedded = fixture(1);
        assert!(load_with(&[], &[]).unwrap_err().contains("not embedded"));
        for args in [
            vec!["--carrier".into()],
            vec!["--carrier".into(), "--json".into()],
        ] {
            assert!(load_with(&args, &embedded)
                .unwrap_err()
                .contains("requires a file path"));
        }
        let dir = Temporary::new();
        let path = dir.0.join("missing.so");
        let args = vec!["--carrier".into(), path.to_str().unwrap().into()];
        assert!(load_with(&args, &embedded)
            .unwrap_err()
            .contains("failed to read carrier"));
        std::fs::write(&path, b"not an ELF").unwrap();
        assert!(load_with(&args, &embedded)
            .unwrap_err()
            .contains("arm64 ELF"));
        for offset in [4, 5, 16, 18] {
            let mut bad = embedded.clone();
            bad[offset] = 0;
            assert!(load_with(&[], &bad).unwrap_err().contains("arm64 ELF"));
        }
        let mut no_id = embedded.clone();
        no_id[328] = 0;
        assert!(load_with(&[], &no_id).unwrap_err().contains("GNU build-id"));
        let mut no_setup = embedded.clone();
        no_setup[384 + 2 * 24 + 6] = 0;
        assert!(load_with(&[], &no_setup)
            .unwrap_err()
            .contains("ij2art_setup"));
    }
}
