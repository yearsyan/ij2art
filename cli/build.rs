// Copy out/monitor.bpf.o into OUT_DIR so that include_bytes! can embed it.
// If ./build.sh has not been run first, an empty file is dropped in instead: compilation
// still succeeds, and the error is reported clearly at runtime (this keeps host-side
// testing convenient).
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../out/monitor.bpf.o");
    let dst = out.join("monitor_bpf.o");
    if src.exists() {
        fs::copy(&src, &dst).expect("copy monitor.bpf.o");
    } else {
        fs::write(&dst, []).expect("write empty stub");
    }
    println!("cargo:rerun-if-changed={}", src.display());

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
