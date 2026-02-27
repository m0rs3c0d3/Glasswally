# Glasswally

**Real-time LLM distillation attack detection via eBPF**

Glasswally detects industrial-scale model distillation campaigns — where adversaries use thousands of coordinated accounts to systematically extract AI model capabilities — using a multi-signal detection pipeline with a Rust/tokio hot path and eBPF kernel instrumentation.

Built in response to [Anthropic's Feb 2026 disclosure](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks) documenting campaigns by DeepSeek (150K exchanges), Moonshot (3.4M exchanges), and MiniMax (13M exchanges) against Claude.

---

## Why eBPF

Traditional detection reads API gateway logs *after* requests are processed. Glasswally hooks into the kernel at `ssl_write()` / `ssl_read()` — *before* TLS encryption — capturing plaintext at the source with zero-copy perf ring buffers.

```
Traditional:  [Request] → [TLS Encrypt] → [Network] → [Log File] → [Detection]
Glasswally:   [Request] → [ssl_write() uprobe] → [Detection]  ← zero-copy, plaintext
```

This also directly counters **[Fingerprint Suite](https://github.com/apify/fingerprint-suite)** and similar tools that spoof User-Agent headers and browser JS APIs to evade detection:

| What Fingerprint Suite spoofs | What Glasswally sees instead |
|---|---|
| User-Agent header | JA3 TLS fingerprint of the actual client library |
| HTTP headers | Header arrival order at the transport layer |
| Browser JS APIs | Irrelevant — we're in the kernel, below JS |

---

## Detection Signals

| Worker | Signal | Catches |
|---|---|---|
| `fingerprint` | JA3 hash + HTTP header order entropy | Fingerprint Suite, UA spoofing |
| `velocity` | RPH, timing regularity (Kendall tau), token CV | Scripted automation |
| `cot` | Aho-Corasick pattern match (33 patterns) | DeepSeek CoT extraction |
| `hydra` | Graph cluster via shared payment/IP/subnet | Hydra proxy networks |
| `pivot` | Coordinated model version switch | MiniMax-style pivot behavior |

Signals are fused with a weighted ensemble (fingerprint 30%, velocity 23%, CoT 23%, hydra 14%, pivot 10%) with geo uplift for restricted regions and cluster-level floor raising.

---

## Enforcement Actions

All output is append-only JSONL — wire to your enforcement API or Kafka topics.

| File | Action | Trigger |
|---|---|---|
| `enforcement_actions.jsonl` | SUSPEND / CLUSTER_TAKEDOWN | Score ≥ 0.72 (CRITICAL) |
| `rate_limit_commands.jsonl` | RATE_LIMIT | Score ≥ 0.35 (MEDIUM) |
| `analyst_queue.jsonl` | FLAG_FOR_REVIEW | Score ≥ 0.55 (HIGH) |
| `ioc_bundles.jsonl` | IOC intel bundle | CLUSTER_TAKEDOWN fired |
| `audit_log.jsonl` | All actions | Always |

IOC bundles include: IP ranges, subnets, payment hashes, **JA3 hashes**, **header order hashes**, account IDs — ready for cross-provider sharing.

---

## Build

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Nightly + BPF target (for eBPF mode)
rustup toolchain install nightly
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly

# bpftool (for vmlinux.h generation)
sudo apt-get install linux-tools-common linux-tools-$(uname -r)
```

### Kernel requirements (eBPF mode only)

- Linux **5.8+**
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_UPROBE_EVENTS=y`
- `CONFIG_DEBUG_INFO_BTF=y` (for CO-RE)
- `CAP_BPF` capability or root

Check your kernel: `uname -r` — anything 5.8+ on Ubuntu 20.04+ works.

### Compile

```bash
# eBPF programs (kernel side)
cargo xtask build-ebpf

# Userspace binary with eBPF support
cargo build --release --package glasswally --features live-ebpf

# Userspace only (tail/replay modes, no kernel requirements)
cargo build --release --package glasswally
```

---

## Run

### eBPF mode (production — Linux 5.8+)

```bash
# Requires CAP_BPF or root
sudo ./target/release/glasswally --mode ebpf --output /var/glasswally/output
```

Glasswally attaches uprobes to `libssl.so ssl_write` and `ssl_read`, capturing all plaintext API traffic passing through OpenSSL/BoringSSL on the host.

### Tail mode (staging — any platform)

Point at your API gateway's JSONL access log:

```bash
glasswally --mode tail \
  --path /var/log/nginx/api_access.jsonl \
  --output /var/glasswally/output
```

**nginx log format for Glasswally:**

```nginx
log_format glasswally_json escape=json
  '{"request_id":"$request_id",'
  '"account_id":"$http_x_account_id",'
  '"timestamp":"$time_iso8601",'
  '"ip_address":"$remote_addr",'
  '"user_agent":"$http_user_agent",'
  '"model":"$arg_model",'
  '"prompt":"$request_body",'
  '"token_count":$content_length,'
  '"country_code":"$geoip2_country_code",'
  '"payment_method_hash":"$http_x_payment_hash"}';

access_log /var/log/nginx/api_access.jsonl glasswally_json;
```

### Replay mode (testing/research)

```bash
# Replay at 10x speed for faster evaluation
glasswally --mode replay \
  --path captured_traffic.jsonl \
  --speed 10.0 \
  --output /tmp/glasswally_test
```

---

## Project Structure

```
glasswally/
├── glasswally-ebpf/        BPF kernel programs (bpfel-unknown-none target)
│   └── src/main.rs         ssl_write/ssl_read uprobes, tcp_connect kprobe
├── glasswally/             Userspace pipeline (Linux/macOS/Windows)
│   ├── src/
│   │   ├── main.rs         tokio entry point, CLI, event routing
│   │   ├── loader.rs       aya BPF loader, uprobe attachment
│   │   ├── events.rs       all shared types
│   │   ├── http_reconstruct.rs  HTTP/1.1 reconstruction from SSL captures
│   │   ├── state/window.rs lock-free sliding windows (DashMap)
│   │   ├── workers/        detection workers (velocity, CoT, fingerprint, hydra, pivot)
│   │   └── engine/         signal fusion + enforcement dispatcher
│   └── build.rs            embeds BPF bytecode at compile time
├── xtask/                  build tooling (cargo xtask build-ebpf)
└── python/                 semantic ML bridge (TF-IDF, NetworkX — from sentinel/)
```

---

## Performance

| Metric | Value |
|---|---|
| Throughput (tail/replay mode) | ~500K events/sec |
| eBPF capture overhead | <1% CPU at 100Krps |
| JA3 parse time | ~2µs per packet |
| CoT pattern match (Aho-Corasick) | ~8µs per prompt |
| Memory (100K tracked accounts) | ~200MB |
| Alert latency (tail mode) | <500µs |

---

## Related Work

- Anthropic disclosure: [Detecting and Preventing Distillation Attacks](https://www.anthropic.com/news/detecting-and-preventing-distillation-attacks)
- JA3 fingerprinting: [Salesforce Engineering](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967)
- aya-rs eBPF framework: [aya.rs](https://aya-rs.dev)

---

## License

MIT — see [LICENSE](LICENSE)
