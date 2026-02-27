# Glasswally Deployment Guide

## Overview

Glasswally operates in three modes:

| Mode | Description | Use case |
|------|-------------|----------|
| `ebpf` | Live kernel uprobes on TLS write/read | Production (Linux 5.8+, root) |
| `tail` | Tail a JSONL API gateway access log | Staging, SIEM integration |
| `eval` | Off-line F1/precision/recall evaluation | Research, threshold tuning |

---

## Prerequisites

### Production (eBPF mode)
- Linux kernel 5.8+ (`uname -r`)
- Kernel config: `CONFIG_BPF_SYSCALL=y`, `CONFIG_UPROBE_EVENTS=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Root or `CAP_BPF + CAP_PERFMON` capabilities
- Rust 1.82+ stable + nightly (for BPF cross-compile)

### Tail mode (staging / no root)
- Any Linux/macOS/Windows host
- API gateway must write JSONL to a file (see format below)

---

## Building

### Userspace binary only (tail mode)
```bash
cargo build --release -p glasswally
# Binary at: target/release/glasswally
```

### With live eBPF support
```bash
# Build BPF kernel programs
rustup toolchain install nightly
rustup target add bpfel-unknown-none --toolchain nightly
rustup component add rust-src --toolchain nightly
cargo xtask build-ebpf --release

# Build userspace with embedded BPF bytecode
cargo build --release -p glasswally --features live-ebpf
```

---

## Deployment topologies

### 1. Standalone + nginx gateway (recommended staging)

```
[Client] → [nginx] → [LLM backend]
                ↓ JSONL access log
          [Glasswally --mode tail]
                ↓ enforcement JSONL
          [enforcement-agent] → [block / rate-limit API key]
```

**nginx log format** (`/etc/nginx/nginx.conf`):

```nginx
log_format glasswally escape=json
  '{"account_id":"$http_authorization",'
  '"timestamp":"$time_iso8601",'
  '"model":"$upstream_http_x_model",'
  '"prompt":"",'
  '"client_ip":"$remote_addr",'
  '"user_agent":"$http_user_agent"}';

access_log /var/log/nginx/llm_access.jsonl glasswally;
```

Run Glasswally:
```bash
sudo glasswally \
  --mode tail \
  --path /var/log/nginx/llm_access.jsonl \
  --output-dir /var/lib/glasswally/output \
  --metrics-addr 127.0.0.1:9090
```

### 2. Docker Compose (full stack)

```bash
git clone https://github.com/m0rs3c0d3/glasswally
cd glasswally
docker compose up --build -d

# Verify
curl -s http://localhost:9090/metrics | grep glasswally_events_total
# Grafana: http://localhost:3000  (admin/admin)
```

### 3. Kubernetes (eBPF DaemonSet)

Deploy as a DaemonSet with `hostPID: true` and `privileged: true`:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: glasswally
  namespace: security
spec:
  selector:
    matchLabels:
      app: glasswally
  template:
    spec:
      hostPID: true
      containers:
        - name: glasswally
          image: ghcr.io/m0rs3c0d3/glasswally:latest
          securityContext:
            privileged: true
          volumeMounts:
            - name: debugfs
              mountPath: /sys/kernel/debug
              readOnly: true
          command: ["glasswally", "--mode", "ebpf", "--metrics-addr", "0.0.0.0:9090"]
          ports:
            - containerPort: 9090  # Prometheus
            - containerPort: 50051 # gRPC
      volumes:
        - name: debugfs
          hostPath:
            path: /sys/kernel/debug
```

---

## API Gateway Integration (gRPC suspend check)

Glasswally exposes a length-prefixed JSON API on port 50051. Before forwarding
each request to the LLM backend, the gateway calls:

```
Request:  { "account_id": "sk-xxxx..." }
Response: { "account_id": "sk-xxxx...", "status": "ok|watch|rate_limited|suspended",
            "composite_score": 0.72, "evidence": ["CoT sweep: 8/10 matches"] }
```

**Envoy ext_proc filter** example (pseudo-config):
```yaml
http_filters:
  - name: envoy.filters.http.ext_proc
    typed_config:
      grpc_service:
        envoy_grpc:
          cluster_name: glasswally
      processing_mode:
        request_header_mode: SEND
```

---

## Outputs

### Enforcement JSONL (`output/enforcement.jsonl`)
```json
{
  "timestamp": "2024-01-15T10:23:45Z",
  "account_id": "sk-abc123",
  "action": "SUSPEND_ACCOUNT",
  "risk_tier": "CRITICAL",
  "composite_score": 0.84,
  "evidence": ["CoT sweep: 8/10 matches", "Fingerprint cluster: 12 accounts same JA3"]
}
```

### IOC Bundles (`output/ioc_bundles.jsonl`)
Account clusters, shared ASNs, and IOC indicators for threat intelligence sharing.

### Prometheus metrics (`http://host:9090/metrics`)
```
glasswally_events_total
glasswally_alerts_critical_total
glasswally_alerts_high_total
glasswally_composite_score_bucket{le="0.35|0.55|0.72|1.0"}
glasswally_worker_signals_total{worker="fingerprint|cot|..."}
```

---

## Configuration reference

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | required | `ebpf`, `tail`, or `eval` |
| `--path` | — | Log path (tail/eval mode) |
| `--output-dir` | `./output` | Enforcement + IOC output directory |
| `--metrics-addr` | `127.0.0.1:9090` | Prometheus `/metrics` bind address |
| `--grpc-addr` | `127.0.0.1:50051` | gRPC query API bind address |
| `--threshold` | `0.35` | Minimum composite score to emit an alert |
| `--eval-threshold` | `0.52` | Score threshold used in eval mode |

Environment variables (override Redis/Kafka defaults):
```bash
GLASSWALLY_REDIS_URL=redis://redis:6379
GLASSWALLY_KAFKA_BROKERS=kafka1:9092,kafka2:9092
RUST_LOG=glasswally=info     # or =debug for verbose output
```

---

## Tuning detection thresholds

Run the evaluation harness to find the optimal threshold for your traffic mix:

```bash
# Capture 1 week of labeled traffic, then:
cargo xtask evaluate datasets/my_labeled.jsonl
```

The report prints a threshold sweep table. Pick the threshold that maximizes
F1 or minimizes FPR depending on your operational tolerance.

---

## Operational runbook

### Responding to a CLUSTER_TAKEDOWN alert
1. Review `output/enforcement.jsonl` for the cluster member list.
2. Revoke API keys for all cluster members via your key management API.
3. Export the IOC bundle to your threat intelligence platform.
4. Check `output/ioc_bundles.jsonl` for shared ASNs to block at the edge.

### False positive rate too high
1. Increase `--threshold` from `0.35` to `0.45`.
2. Run `cargo xtask evaluate` to measure impact on F1.
3. Consider disabling the lowest-precision workers by setting their weight to 0.0
   in `engine/fusion.rs` and adjusting others to compensate.

### Upgrading
```bash
git pull
cargo build --release -p glasswally --features live-ebpf
sudo systemctl restart glasswally
```
