// xtask/src/main.rs
//
// Glasswally build tooling — cargo xtask pattern.
//
// Commands:
//   cargo xtask build-ebpf          # compile BPF programs to bytecode
//   cargo xtask run                 # build-ebpf then cargo run
//   cargo xtask run --release       # release build
//   cargo xtask vmlinux             # generate vmlinux.h from running kernel
//
// How it works:
//   BPF programs must be compiled to a special target (bpfel-unknown-none)
//   using a nightly toolchain. This xtask handles that so developers just
//   run `cargo xtask build-ebpf` without knowing the cross-compilation details.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let task = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let release = args.contains(&"--release".to_string());

    match task {
        "build-ebpf"  => build_ebpf(release),
        "run"         => { build_ebpf(release); run_userspace(release); }
        "vmlinux"     => generate_vmlinux(),
        "check"       => check(),
        "help" | _    => print_help(),
    }
}

fn workspace_root() -> PathBuf {
    // xtask lives in workspace_root/xtask/
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask should be in workspace root")
        .to_path_buf()
}

/// Compile BPF programs to bytecode.
///
/// Requires:
///   rustup target add bpfel-unknown-none
///   rustup toolchain install nightly
///   rustup component add rust-src --toolchain nightly
///
/// The compiled object is placed at:
///   target/bpfel-unknown-none/release/glasswally-ebpf
fn build_ebpf(release: bool) {
    println!("Building eBPF programs...");

    let root   = workspace_root();
    let target = "bpfel-unknown-none";

    // Ensure the BPF target is installed
    let status = Command::new("rustup")
        .args(&["target", "add", target, "--toolchain", "nightly"])
        .status()
        .expect("Failed to run rustup");
    if !status.success() {
        eprintln!("Warning: Could not add BPF target. Run: rustup target add {} --toolchain nightly", target);
    }

    // Build the BPF crate targeting BPF VM
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root)
        .args(&[
            "+nightly",
            "build",
            "--package", "glasswally-ebpf",
            "--target", target,
            "-Z", "build-std=core",  // BPF needs no_std core
        ]);

    if release {
        cmd.arg("--release");
    }

    // Tell the compiler this is a BPF build
    cmd.env("CARGO_ENCODED_RUSTFLAGS", "-C panic=abort");

    let status = cmd.status().expect("Failed to build eBPF programs");
    if !status.success() {
        eprintln!("eBPF build failed. Check output above.");
        std::process::exit(1);
    }

    let profile = if release { "release" } else { "debug" };
    let obj_path = root.join(format!(
        "target/{}/{}/glasswally-ebpf",
        target, profile
    ));

    println!("eBPF object built: {}", obj_path.display());
    println!("Copy to userspace OUT_DIR for embedding...");

    // The aya build.rs in glasswally/ will embed this via include_bytes_aligned!()
    // when building with --features live-ebpf
}

/// Run the userspace binary (after BPF programs are built).
fn run_userspace(release: bool) {
    let root = workspace_root();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root)
        .args(&["run", "--package", "glasswally", "--features", "live-ebpf"]);
    if release { cmd.arg("--release"); }

    let status = cmd.status().expect("Failed to run glasswally");
    if !status.success() {
        std::process::exit(1);
    }
}

/// Generate vmlinux.h from the running kernel's BTF data.
/// This is required for CO-RE (Compile Once Run Everywhere) BPF programs.
///
/// Requires: bpftool installed (apt install linux-tools-common)
fn generate_vmlinux() {
    println!("Generating vmlinux.h from running kernel BTF...");

    let root   = workspace_root();
    let outdir = root.join("glasswally-ebpf/src/vmlinux.h");

    // Check BTF availability
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        eprintln!("Error: /sys/kernel/btf/vmlinux not found.");
        eprintln!("Your kernel may not have BTF enabled.");
        eprintln!("Check: CONFIG_DEBUG_INFO_BTF=y in kernel config.");
        std::process::exit(1);
    }

    let status = Command::new("bpftool")
        .args(&["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
        .stdout(std::fs::File::create(&outdir).expect("Cannot create vmlinux.h"))
        .status()
        .expect("bpftool not found — install linux-tools-common");

    if status.success() {
        println!("vmlinux.h written to {}", outdir.display());
    } else {
        eprintln!("bpftool failed. Is it installed? apt install linux-tools-$(uname -r)");
        std::process::exit(1);
    }
}

fn check() {
    let root = workspace_root();
    // Check userspace crate
    let status = Command::new("cargo")
        .current_dir(&root)
        .args(&["check", "--package", "glasswally"])
        .status()
        .expect("cargo check failed");
    if !status.success() { std::process::exit(1); }
    println!("All checks passed.");
}

fn print_help() {
    println!("Glasswally build tooling\n");
    println!("USAGE:");
    println!("  cargo xtask <command> [--release]\n");
    println!("COMMANDS:");
    println!("  build-ebpf   Compile BPF kernel programs to bytecode");
    println!("  run          Build BPF + run userspace pipeline");
    println!("  vmlinux      Generate vmlinux.h from running kernel BTF");
    println!("  check        Run cargo check on all crates");
    println!("\nPREREQUISITES:");
    println!("  rustup toolchain install nightly");
    println!("  rustup target add bpfel-unknown-none --toolchain nightly");
    println!("  rustup component add rust-src --toolchain nightly");
    println!("  apt install linux-tools-common bpftool    # for vmlinux cmd");
    println!("  Kernel: Linux 5.8+ with CONFIG_BPF_SYSCALL=y CONFIG_UPROBE_EVENTS=y");
}
