// build.rs — embed compiled BPF bytecode at compile time.
//
// Only relevant when building with --features live-ebpf: copies the object
// produced by `cargo xtask build-ebpf` into OUT_DIR, where loader.rs embeds
// it via include_bytes_aligned!(concat!(env!("OUT_DIR"), "/glasswally-ebpf")).

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../glasswally-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../target/bpfel-unknown-none/release/glasswally-ebpf");
    println!("cargo:rerun-if-changed=../target/bpfel-unknown-none/debug/glasswally-ebpf");

    if std::env::var_os("CARGO_FEATURE_LIVE_EBPF").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let candidates = [
        manifest_dir.join("../target/bpfel-unknown-none/release/glasswally-ebpf"),
        manifest_dir.join("../target/bpfel-unknown-none/debug/glasswally-ebpf"),
    ];
    let obj = candidates.iter().find(|p| p.exists()).unwrap_or_else(|| {
        panic!(
            "live-ebpf feature enabled but no compiled BPF object found.\n\
             Run `cargo xtask build-ebpf` first (expected {})",
            candidates[0].display()
        )
    });

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("glasswally-ebpf");
    std::fs::copy(obj, &out).expect("failed to copy BPF object into OUT_DIR");
}
