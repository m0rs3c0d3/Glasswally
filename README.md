# Glasswally

[![CI](https://github.com/noisyloop/Glasswally/actions/workflows/ci.yml/badge.svg)](https://github.com/noisyloop/Glasswally/actions/workflows/ci.yml)

**Multi-signal detection of LLM distillation campaigns** — a Rust/tokio pipeline that fuses 16 behavioral and infrastructure signals to flag coordinated model-extraction traffic, with optional eBPF TLS capture as a live event source.

Distillation attacks harvest model outputs at scale through ordinary API calls: thousands of accounts, chain-of-thought elicitation prompts, systematic capability sweeps. No single request is malicious; the campaign is only visible in the aggregate. Glasswally ingests API request events, maintains sliding-window state per account, clusters accounts by shared infrastructure (payment methods, subnets, TLS fingerprints), and scores every event through 16 concurrent detection workers whose signals are fused into a per-account risk decision.

The design is informed by [Anthropic's disclosure of large-scale distillation campaigns](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks) (February 2026).

## Quickstart — replay demo (no root, no eBPF)

Requires only stable Rust (tested on Linux).

```bash
git clone https://github.com/noisyloop/Glasswally
cd Glasswally
cargo xtask demo
```

This replays `examples/sample_events.jsonl` — 3,000 synthetic API-gateway events (150 benign users interleaved with 3 coordinated distillation campaigns) — through the full detection pipeline at 60× speed (~20 s) and prints alerts as accounts cross the risk threshold:

```
🔵 MEDIUM → RATE_LIMIT
  Account : sk-2d83b4b85e32f5a365e22713
  Score   : 0.3712
  Cluster : Some(1)
  Evidence: ua_tls_mismatch:ua=browser,ja3=script:d7b2b1e8 | ja3s_mismatch:server_hello=script_client,ua=browser:06b609f6 | missing_browser_headers:accept-language [campaign_0001]

Replay complete — 3000 events, 174 accounts, 19 clusters. Enforcement output in ./glasswally_output
```

(The `[campaign_0001]` tag is the dataset's ground-truth label, shown because the sample events carry one — live traffic has no such field.)

Replay, tail, and eBPF capture all feed the **same** event channel and pipeline — there is no demo-only code path. Enforcement decisions (rate-limit commands, analyst queue, audit log, IOC bundles) are appended as JSONL under `./glasswally_output/`.

Equivalent direct invocation, plus the other file-driven modes:

```bash
cargo run --release -- --mode replay --path examples/sample_events.jsonl --speed 60
cargo run --release -- --mode tail   --path /var/log/api/access.jsonl      # follow a live log
cargo run --release -- --mode eval   --path datasets/labeled_5k.jsonl      # labeled evaluation
```

Note on replay speed: sliding windows are anchored to wall clock, so replaying at N× inflates rate-based signals (velocity, session cadence) by roughly N×. Use `--mode eval` when you want metrics at true timing.

Regenerate or customize datasets with the deterministic generator (Python 3, stdlib only):

```bash
python3 tools/loggen.py --output my_events.jsonl --count 5000 --seed 7 --campaigns 3
```

## Detection signals

The 16 workers run concurrently per event (`glasswally/src/workers/`). Fusion weights are from `glasswally/src/engine/fusion.rs` and sum to 1.0 (enforced by a unit test).

| Worker | Weight | Signal |
|---|---|---|
| `fingerprint` | 0.14 | JA3/JA3S TLS fingerprint vs. claimed User-Agent (script TLS under a browser UA), JA3 rotation, header-order entropy, missing browser headers |
| `velocity` | 0.10 | Requests/hour, inter-arrival regularity (CV), token-count uniformity, off-hours ratio |
| `cot` | 0.09 | Aho-Corasick match of chain-of-thought elicitation phrases + capability-domain sweep heatmap |
| `embed` | 0.08 | Paraphrase-resistant semantic similarity: hashed n-gram embeddings vs. 24 canonical extraction archetypes |
| `hydra` | 0.08 | Infrastructure cluster scoring (accounts linked by shared payment method, /24 subnet, org, JA3) + payment BIN batch analysis |
| `timing_cluster` | 0.07 | Cross-account synchronized bursts: ≥5 accounts firing in the same 1-second bucket on a recurring cadence |
| `asn_classifier` | 0.07 | Source ASN classified as datacenter/cloud hosting; cloud-majority clusters |
| `h2_grpc` | 0.06 | HTTP/2 SETTINGS-frame fingerprint vs. User-Agent (aiohttp/httpx/Go SETTINGS under a browser UA), gRPC transport detection |
| `role_preamble` | 0.06 | System-prompt (role preamble) hash reuse within an account and collisions across ≥5 accounts |
| `pivot` | 0.05 | Coordinated model switches — many clustered accounts pivoting to the same model within hours |
| `biometric` | 0.05 | Prompt-sequence entropy: structural template reuse, uniform prompt lengths, repeated prefixes |
| `watermark` | 0.04 | Probes against the response-watermarking system: zero-width characters inbound, watermark-related prompts |
| `session_gap` | 0.04 | Cron-like inter-session gap regularity and uniform session lengths |
| `token_budget` | 0.03 | Greedy `max_tokens` requests and geometric/arithmetic `max_tokens` sweeps |
| `refusal_probe` | 0.02 | Density and category coverage of refusal-boundary probing prompts |
| `sequence_model` | 0.02 | Markov chain over prompt topics: uniform stationary distribution + predictable transitions |

**Fusion** (`engine/fusion.rs`): each signal contributes `score × (0.4 + 0.6 × confidence) × weight`; the composite gets a 1.3× uplift for CN-origin traffic and +0.08 when the account sits in a cluster of ≥5. Tiers: ≥0.72 **Critical** → suspend account (cluster takedown + IOC bundle if the cluster has ≥3 members), ≥0.55 **High** → inject canary token for response watermarking, ≥0.35 **Medium** → rate limit. Per-account alert cooldown is 600 s.

## Evaluation

The repo ships a labeled synthetic dataset and an evaluation harness:

```bash
cargo xtask evaluate                                # datasets/labeled_5k.jsonl
cargo xtask evaluate examples/sample_events.jsonl   # or any labeled JSONL
```

On `datasets/labeled_5k.jsonl` (5,000 events, 1,056 positive, threshold 0.35) this currently prints precision 1.000, recall 0.913, F1 0.955, FPR 0.000, plus per-worker metrics and a score histogram. **Read these numbers for what they are**: the events are synthetic, generated by `tools/loggen.py`, whose campaign model was written with full knowledge of the detectors. They demonstrate that the pipeline is wired correctly end to end — they say nothing about real-world efficacy. No benchmarks against real traffic exist yet. There are no throughput/latency benchmarks in this repo either; overhead claims you may find in older revisions were not reproducible and have been removed.

Not every worker fires on the bundled data (e.g. `embed`, `watermark`, `refusal_probe` see no qualifying traffic in it).

## eBPF capture mode (Linux, privileged)

The eBPF path captures plaintext at the TLS library boundary — uprobes on `SSL_write`/`SSL_read` (OpenSSL/BoringSSL), `PR_Write`/`PR_Read` (NSS), and `crypto/tls.(*Conn).Write/Read` offsets in Go binaries — reconstructs HTTP requests from the captures, and feeds them into the same pipeline channel as replay/tail.

Real prerequisites, as enforced or assumed by the code:

- **Linux 5.8+** with `CONFIG_BPF_SYSCALL=y` and uprobe support. 5.8 is where `CAP_BPF`/`CAP_PERFMON` were introduced; there is no runtime version probe — on older kernels the program load/attach simply fails.
- **`CAP_BPF` + `CAP_PERFMON`, or root.**
- **Build toolchain**: nightly Rust with `rust-src`, plus `bpf-linker` (`cargo install bpf-linker`). The BPF programs do **not** use CO-RE/BTF (they read no kernel structs), so `/sys/kernel/btf/vmlinux` is only needed if you use `cargo xtask vmlinux` to regenerate `vmlinux.h` for future CO-RE work.
- A target process that actually uses one of the hooked TLS libraries, discoverable at the paths scanned in `glasswally/src/loader.rs`.

```bash
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker

cargo xtask build-ebpf                                    # compile BPF bytecode
cargo build --release --features live-ebpf -p glasswally  # embed it in the daemon
sudo ./target/release/glasswally --mode ebpf
```

`--mode ebpf` without the `live-ebpf` feature exits with an error rather than silently degrading to file tailing.

Known limitation, stated plainly: kernel captures can't see payment methods, ASN, geo, or TLS-handshake fingerprints (JA3 is computed from the ClientHello, which uprobes on `SSL_write` never observe). Events from the eBPF source therefore carry empty enrichment fields and only the content/timing workers contribute; the enrichment join against gateway metadata is future work.

## Repository layout

```
glasswally/            userspace daemon: pipeline, 16 workers, fusion, dispatcher
glasswally-ebpf/       BPF programs (excluded from the workspace; built via xtask)
xtask/                 build tooling: build-ebpf, demo, evaluate, vmlinux
examples/              sample_events.jsonl — dataset used by `cargo xtask demo`
datasets/              labeled_5k.jsonl — default evaluation dataset
tools/loggen.py        deterministic synthetic event generator
docs/, THREAT_MODEL.md threat model and design notes
falco/, yara/, monitoring/  companion rules and dashboards (not wired to the daemon)
```

## Status / roadmap

Implemented and exercised by the demo/eval commands above:

- [x] 16 detection workers, weighted fusion, tiered enforcement decisions
- [x] Sliding-window state store with infrastructure clustering
- [x] File sources (replay/tail), labeled evaluation harness, synthetic generator
- [x] eBPF TLS capture → HTTP reconstruction → pipeline (builds and attaches; enrichment fields empty as noted above)
- [x] JSONL enforcement outputs: rate-limit commands, analyst queue, audit log, IOC bundles

Present in the source tree but **not implemented as working integrations** — these modules compile but are not wired into the running daemon, and some are simulated backends:

- [ ] `grpc_api.rs` — account-status query API (plain TCP/JSON, not actually gRPC; not started by `main`)
- [ ] `kafka_output.rs` — Kafka publisher (simulated in-memory backend; no Kafka client dependency)
- [ ] `redis_state.rs` — state persistence (not wired; state is in-memory only and lost on restart)
- [ ] `otel.rs` — metrics exporter (not wired)
- [ ] `load_shedder.rs` — backpressure control (not wired)
- [ ] `ioc_feed.rs` — cross-provider IOC sharing (not wired)
- [ ] `redteam.rs` — adversarial-evasion evaluation harness (not wired)
- [ ] Canary/watermark response injection — detection and token registry exist; nothing modifies responses
- [ ] eBPF enrichment join (JA3/ASN/geo/payment for kernel-captured events)
- [ ] Evaluation against non-synthetic traffic

## License

MIT.
