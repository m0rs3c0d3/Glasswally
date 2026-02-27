// build.rs — embed compiled BPF bytecode at compile time.
//
// Only relevant when building with --features live-ebpf.
// The bytecode is produced by: cargo xtask build-ebpf

fn main() {
    // Re-run if BPF source or compiled object changes.
    println!("cargo:rerun-if-changed=../glasswally-ebpf/src/main.rs");
    println!(
        "cargo:rerun-if-changed=../target/bpfel-unknown-none/release/glasswally-ebpf"
    );
}
