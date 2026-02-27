# Glasswally Falco Plugin

## Overview

The Glasswally Falco plugin exposes LLM distillation detection signals as Falco
events, enabling Kubernetes security teams to:

1. Alert on distillation campaigns via Falco rules in existing SOC tooling
2. Correlate with pod-level syscall events (unusual process spawning, network connections)
3. Trigger automated Kubernetes Network Policy enforcement to isolate suspicious pods
4. Integrate with OPA/Gatekeeper for admission control on new API consumer pods

## Plugin Architecture

The plugin implements the [Falco Plugin SDK](https://falco.org/docs/plugins/go-sdk-walkthrough/)
(Go SDK, v0.7+) using the `plugin_event_source` capability.

```
Glasswally Daemon
      │
      │ (Unix socket / HTTP /events)
      ▼
Falco Plugin (glasswally.so)
      │
      │ falco_event{source="glasswally"}
      ▼
Falco Engine → Rules evaluation
      │
      │ Falco alert
      ▼
Falcosidekick → Slack / PagerDuty / SIEM
```

## Event Schema

Each Glasswally event emitted to Falco has the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `gw.account_id` | string | API account identifier |
| `gw.composite_score` | float | Fused risk score (0.0–1.0) |
| `gw.tier` | string | LOW \| MEDIUM \| HIGH \| CRITICAL |
| `gw.action` | string | Enforcement action taken |
| `gw.cluster_id` | uint64 | Hydra cluster ID (0 = no cluster) |
| `gw.n_accounts_in_cluster` | uint64 | Cluster size |
| `gw.top_evidence` | string | Pipe-separated evidence strings |
| `gw.worker_fired` | string | Comma-separated list of fired workers |
| `gw.country_code` | string | Source country code |
| `gw.ip_address` | string | Source IP (may be subnet representative) |

## Example Falco Rules

```yaml
# falco/glasswally_rules.yaml

- rule: LLM Distillation Campaign Detected
  desc: >
    Glasswally detected a CRITICAL-tier LLM distillation campaign.
    A cluster of accounts is systematically extracting model capabilities.
  condition: >
    gw.tier = "CRITICAL" and gw.n_accounts_in_cluster >= 5
  output: >
    LLM distillation campaign: account=%gw.account_id
    cluster=%gw.cluster_id size=%gw.n_accounts_in_cluster
    score=%gw.composite_score evidence=%gw.top_evidence
  priority: CRITICAL
  tags: [llm, distillation, glasswally]

- rule: LLM Distillation High Risk Account
  desc: >
    Glasswally flagged a HIGH-risk account. Canary injection initiated.
  condition: >
    gw.tier = "HIGH"
  output: >
    High-risk LLM account: account=%gw.account_id
    score=%gw.composite_score workers=%gw.worker_fired
  priority: WARNING
  tags: [llm, distillation, glasswally]

- rule: Distillation Cluster Takedown
  desc: >
    Glasswally has taken down a distillation cluster.
    All member accounts suspended.
  condition: >
    gw.action = "CLUSTER_TAKEDOWN"
  output: >
    Cluster takedown executed: cluster=%gw.cluster_id
    affected_accounts=%gw.n_accounts_in_cluster
    score=%gw.composite_score
  priority: CRITICAL
  tags: [llm, distillation, glasswally, enforcement]

- rule: Canary Token Triggered
  desc: >
    A canary token injected in a suspected distillation response has been
    triggered — confirming the account is reproducing scraped content.
  condition: >
    gw.action = "INJECT_CANARY" and gw.top_evidence contains "canary_triggered"
  output: >
    Canary triggered — distillation confirmed: account=%gw.account_id
    score=%gw.composite_score
  priority: CRITICAL
  tags: [llm, distillation, canary, glasswally]
```

## Installation

### 1. Build the plugin

```bash
cargo xtask build-falco-plugin
# Outputs: target/release/libglasswally_falco.so
```

### 2. Deploy plugin to Falco

```bash
# Copy plugin to Falco plugin directory
cp target/release/libglasswally_falco.so /usr/share/falco/plugins/

# Add to /etc/falco/falco.yaml:
plugins:
  - name: glasswally
    library_path: /usr/share/falco/plugins/libglasswally_falco.so
    init_config:
      glasswally_socket: /run/glasswally/events.sock
      reconnect_interval_ms: 1000

load_plugins: [glasswally]
```

### 3. Load rules

```bash
cp falco/glasswally_rules.yaml /etc/falco/rules.d/
systemctl reload falco
```

## Kubernetes Network Policy Automation

Use [Falcosidekick](https://github.com/falcosecurity/falcosidekick) with the
`kubeless` or `webhook` output to trigger automated NetworkPolicy enforcement:

```yaml
# Triggered on CLUSTER_TAKEDOWN: isolate all pods with matching labels
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: glasswally-isolate-cluster-${CLUSTER_ID}
spec:
  podSelector:
    matchLabels:
      glasswally/cluster-id: "${CLUSTER_ID}"
  policyTypes:
    - Egress
  egress: []   # Deny all egress — blocks API calls to LLM backend
```

## Plugin Implementation Reference

The Falco plugin source is in `falco/plugin/` (Go):

```go
// falco/plugin/main.go — skeleton
package main

import (
    "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
    "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

type GlasswallPlugin struct {
    plugins.BasePlugin
    socketPath string
}

func (p *GlasswallPlugin) Info() *plugins.Info {
    return &plugins.Info{
        ID:          42,
        Name:        "glasswally",
        Description: "LLM distillation attack detection events from Glasswally",
        Contact:     "https://github.com/m0rs3c0d3/glasswally",
        Version:     "0.1.0",
        EventSource: "glasswally",
    }
}
```

See the [Falco Plugin SDK documentation](https://falco.org/docs/plugins/) for the
complete plugin development guide.
