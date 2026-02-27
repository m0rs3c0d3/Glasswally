# Contributing to Glasswally

## Quick start

```bash
git clone https://github.com/m0rs3c0d3/glasswally
cd glasswally

# Install Rust stable
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add clippy rustfmt

# Build and test (userspace only — no BPF target required)
cargo check -p glasswally
cargo test  -p glasswally
cargo clippy -p glasswally -- -D warnings
cargo fmt   -p glasswally -- --check
```

## Repository layout

```
glasswally/         Userspace Rust crate (main binary)
  src/
    workers/        One file per detection worker
    engine/         Fusion, dispatcher
    state/          Sliding-window state store
    eval/           Labeled dataset + P/R/F1 framework
glasswally-ebpf/    eBPF kernel programs (BPF cross-compile, see below)
xtask/              Build tooling (cargo xtask)
datasets/           Labeled JSONL datasets
tools/              loggen.py — synthetic log generator
yara/               YARA rules derived from worker patterns
docs/               Evasion cost analysis, differential privacy analysis
falco/              Falco plugin README + rules
monitoring/         Prometheus + Grafana provisioning
```

## Adding a new detection worker

1. Create `glasswally/src/workers/my_worker.rs` — implement `pub async fn analyze(account: &str, store: &StateStore) -> DetectionSignal`.
2. Add `mod my_worker;` to `glasswally/src/workers/mod.rs`.
3. Add the worker to `run_all()` inside `mod.rs` using `tokio::join!`.
4. Add a `WorkerKind::MyWorker` variant to `events.rs`.
5. Add a weight entry to `WEIGHTS` in `engine/fusion.rs` (adjust other weights so sum stays 1.0).
6. The `weights_sum_to_one` test will catch any sum deviation.

## eBPF build (Linux 5.8+ only)

```bash
rustup toolchain install nightly
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly

cargo xtask build-ebpf
cargo build -p glasswally --features live-ebpf
```

## Running in tail mode (no root required)

```bash
# Generate a synthetic log stream
python3 tools/loggen.py --output /tmp/access.jsonl --count 1000

# Tail it
cargo run -p glasswally -- --mode tail --path /tmp/access.jsonl
```

## Running the full stack locally

```bash
docker compose up --build
# Glasswally metrics: http://localhost:9090/metrics
# Grafana:           http://localhost:3000
```

## Evaluation harness

```bash
# Generate labeled dataset (one-time)
python3 tools/loggen.py --output datasets/labeled_5k.jsonl --count 5000

# Run evaluation
cargo xtask evaluate datasets/labeled_5k.jsonl
```

## CI checks (must all pass before merge)

| Check | Command |
|-------|---------|
| Compile | `cargo check -p glasswally` |
| Tests | `cargo test -p glasswally --lib` |
| Lint | `cargo clippy -p glasswally -- -D warnings` |
| Format | `cargo fmt -p glasswally -- --check` |
| YARA | `yara --compile-rules yara/glasswally.yar /dev/null` |

## Code style

- Run `cargo fmt` before every commit.
- No `unwrap()` or `expect()` outside of tests — use `?` and `anyhow::Context`.
- Every new detection signal needs a YARA rule in `yara/glasswally.yar`.
- Update `THREAT_MODEL.md` signal coverage matrix when adding workers.

## Security

Found a vulnerability? Email the maintainers privately. Do **not** open a public issue for security bugs.
