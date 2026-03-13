# Glasswally

[![CI](https://github.com/m0rs3c0d3/Glasswally/actions/workflows/ci.yml/badge.svg)](https://github.com/m0rs3c0d3/Glasswally/actions/workflows/ci.yml)

**Real-time LLM distillation attack detection via eBPF**

Glasswally detects industrial-scale model distillation campaigns — where adversaries use thousands of coordinated accounts to systematically extract AI model capabilities — using a multi-signal detection pipeline with a Rust/tokio hot path and eBPF kernel instrumentation.

Built in response to [Anthropic's Feb 2026 disclosure](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks) documenting campaigns by DeepSeek (150K exchanges), Moonshot (3.4M exchanges), and MiniMax (13M exchanges) against Claude.


## Threat Context

Model distillation attacks are silent. An adversary sends carefully crafted queries to your LLM endpoint, harvests outputs at scale, and trains a surrogate model — extracting your IP without ever touching your weights. Traditional network monitoring doesn't catch it. Log analysis finds it too late. 

Glasswally operates at the kernel level. It doesn't wait for logs.

---

## What It Does

Glasswally hooks directly into LLM inference processes using **eBPF kernel uprobes** — no agent, no sidecar, no instrumentation of your model code. It fingerprints query patterns in real time, detects statistical anomalies consistent with distillation behavior, and alerts before the attack completes.

- **Kernel-level visibility** — eBPF uprobes attach to inference calls at the syscall boundary
- **Distillation fingerprinting** — detects high-volume, low-variance query patterns characteristic of surrogate training
- **MITRE ATT&CK mapped** — threat model aligned to ML-specific attack techniques
- **Zero model modification** — works against any LLM runtime without touching inference code
- **Rust core** — memory-safe, low-overhead, built for production environments

---

## Architecture

```
┌─────────────────────────────────────────┐
│           LLM Inference Process         │
└────────────────────┬────────────────────┘
                     │ uprobe attach
┌────────────────────▼────────────────────┐
│         eBPF Kernel Ring Buffer         │
│   (query fingerprint + timing data)     │
└────────────────────┬────────────────────┘
                     │ perf event stream
┌────────────────────▼────────────────────┐
│        Glasswally Detection Engine      │
│  ┌─────────────┐  ┌────────────────┐   │
│  │  Pattern    │  │   Anomaly      │   │
│  │  Extractor  │  │   Classifier   │   │
│  └─────────────┘  └────────────────┘   │
└────────────────────┬────────────────────┘
                     │
          Alert / Block / Log
```

---

## Threat Model

Glasswally is designed against the following attack surfaces, mapped to MITRE ATLAS:

| Technique | Description | Detection Method |
|-----------|-------------|-----------------|
| Model Inversion | Reconstructing training data via repeated queries | Query variance analysis |
| Distillation Attack | Training surrogate model on harvested outputs | Volume + semantic clustering |
| Membership Inference | Determining if data was in training set | Statistical timing patterns |
| API Probing | Systematic boundary exploration | Rate + diversity fingerprinting |

---

## Quick Start

```bash
# Dependencies: Rust stable, Linux kernel 5.8+, BPF CO-RE support
git clone https://github.com/m0rs3c0d3/glasswally
cd glasswally

# Build the eBPF probe + userspace daemon
cargo build --release

# Attach to a running inference process (requires CAP_BPF)
sudo ./target/release/glasswally --pid $(pgrep ollama) --threshold 0.85
```

---

## Why This Matters

As LLMs become core infrastructure, model IP becomes a primary attack surface. Glasswally is the detection layer this space doesn't have yet.

**Built by a security researcher. For security engineers.**

---

## License

MIT — use it, fork it, deploy it. If you find something interesting, open an issue.

---

*Part of the [m0rs3c0d3](https://github.com/m0rs3c0d3) security tooling portfolio.*
