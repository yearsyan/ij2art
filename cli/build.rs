// Embed build.sh's carrier (which contains the payload) and eBPF object in the CLI.
// Host-only tests can use empty stubs; Android builds must contain both artifacts.
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let android = env::var("CARGO_CFG_TARGET_OS").unwrap() == "android";
    for (source, embedded) in [
        ("monitor.bpf.o", "monitor_bpf.o"),
        ("carrier.so", "carrier.so"),
    ] {
        let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../out")
            .join(source);
        println!("cargo:rerun-if-changed={}", src.display());
        let bytes = match fs::read(&src) {
            Ok(bytes) => bytes,
            Err(e) if !android && e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => panic!("cannot embed {}: {e}; run ./build.sh first", src.display()),
        };
        assert!(
            !android || !bytes.is_empty(),
            "{source} is empty; run ./build.sh first"
        );
        fs::write(out.join(embedded), bytes).expect("write embedded artifact");
    }

    let libbpf =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../third_party/libbpf");
    println!("cargo:rerun-if-changed={}", libbpf.display());
    if matches!(
        env::var("CARGO_CFG_TARGET_OS").unwrap().as_str(),
        "linux" | "android"
    ) {
        cc::Build::new()
            .file(libbpf.join("src/ringbuf.c"))
            .file(libbpf.join("src/support.c"))
            .include(libbpf.join("src"))
            .include(libbpf.join("include"))
            .include(libbpf.join("include/uapi"))
            .flag("-std=gnu11")
            // libbpf's linux/err.h uses bool, but the platform's types.h does not
            // guarantee that it declares that type.
            .flag("-include")
            .flag("stdbool.h")
            .flag("-Wno-sign-compare")
            .flag("-fvisibility=hidden")
            .compile("ij2art_libbpf_ringbuf");
    }
}
