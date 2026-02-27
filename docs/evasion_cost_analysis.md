# Glasswally Evasion Cost Analysis

## Overview

This document quantifies the real-world cost of defeating each Glasswally detection
signal.  Costs are expressed in three dimensions:

1. **Engineering hours** — one-time development to implement the evasion
2. **Recurring infrastructure cost ($/month)** — ongoing operating cost at 10M req/month scale
3. **Throughput impact** — fraction of extraction throughput lost due to the evasion technique

The last column shows whether residual signals survive after the evasion is deployed.

---

## Per-Signal Evasion Cost Table

| Signal | Evasion Technique | Eng Hours | Infra $/mo | Throughput Impact | Residual Signal |
|--------|-------------------|----------:|-----------:|:-----------------:|-----------------|
| **Fingerprint (JA3/JA3S)** | Custom TLS stack (fork BoringSSL, randomize cipher ordering) | 800–2000h | $2,000–8,000 | -40% (latency) | TimingCluster, Embed still fire |
| **Fingerprint (header order)** | Custom HTTP/2 client with randomized header order | 200–400h | $500–2,000 | -10% | JA3S mismatch survives |
| **Velocity** | Spread requests across time (lower RPH) | 8–20h | $50–500 | -60% throughput | SessionGap, TimingCluster survive |
| **CoT (Aho-Corasick)** | Manual paraphrase of all elicitation phrases | 40–120h | $0 | -5% | Embed cosine catches paraphrases |
| **Embed (semantic similarity)** | Fully natural language prompts (no explicit elicitation) | 200–600h | $0 | -15% (lower signal quality) | Biometric entropy, SequenceModel survive |
| **Hydra (cluster graph)** | Unique residential IP per account | 80–160h | $8,000–25,000 | -0% | Payment graph, JA3 cluster survive |
| **TimingCluster (sync burst)** | Sub-second random jitter between all coordinated clients | 40–80h | $1,000–3,000 | -5% | Velocity long-window survives |
| **H2Grpc (SETTINGS)** | Implement per-connection randomized H2 SETTINGS | 160–400h | $0 | -5% | JA3/JA3S library fingerprint survives |
| **Pivot** | Continue with same model, don't switch | 0h | $0 | -0% | Model pivot no longer viable |
| **Biometric (entropy)** | Human-in-the-loop prompt generation | 0h | $150,000+/mo | -80% | TimingCluster, SessionGap survive |
| **Watermark (ZW chars)** | Strip ZW chars from all scraped responses | 4–8h | $0 | -0% | Canary token attribution survives |
| **Watermark (canary token)** | Strip all low-perplexity inserted text | 40–120h | $0 | -3% | Attribution window extends to non-stripped |
| **AsnClassifier** | Residential proxy rotation | 20–40h | $8,000–20,000 | -10% (latency) | H2 fingerprint, timing survive |
| **RolePreamble** | Unique role preamble per request (LLM-generated) | 8–20h | $200–800 | -5% | Embed, SequenceModel survive |
| **SessionGap** | Randomize cron jitter ±30% | 4–8h | $0 | -0% | Burst clustering survives |
| **TokenBudget** | Use constant max_tokens=4096 | 1h | $0 | -10% (shorter responses) | Other signals unaffected |
| **RefusalProbe** | Interleave refusal probes with legitimate prompts | 20–40h | $0 | -5% | Density dilution helps, cross-category sweep survives |
| **SequenceModel** | Randomize topic order (shuffle topic sequence) | 8–20h | $0 | -0% | Stationary entropy breadth survives |

---

## Compound Evasion Packages

Full evasion of Glasswally requires implementing multiple techniques simultaneously.
The following packages represent realistic attacker investment levels:

### Package A: Startup-Grade Evasion (~$50K, 6 months)
- Residential proxy rotation (removes AsnClassifier, Fingerprint IP)
- Manual CoT paraphrase library (partially defeats CoT)
- Velocity smoothing (defeats Velocity)
- Constant max_tokens (defeats TokenBudget)
- Role preamble rotation (defeats RolePreamble)

**Estimated detection reduction**: 55–65%
**Residual Glasswally score**: 0.20–0.35 (below Medium threshold)
**Residual signals**: JA3/H2 fingerprint, TimingCluster, Embed, SequenceModel, Watermark canary

---

### Package B: Nation-State Grade Evasion (~$500K, 18 months)
All of Package A, plus:
- Custom TLS stack with JA3/JA3S randomization
- Randomized H2 SETTINGS per connection
- Human-in-the-loop prompt generation (most expensive component)
- Canary token stripping pipeline
- Sub-second burst randomization

**Estimated detection reduction**: 80–90%
**Residual Glasswally score**: 0.08–0.20 (below Low threshold)
**Residual signals**: Watermark canary attribution (non-stripped), SequenceModel topic breadth (if HIL maintains broad coverage)

---

### Package C: Perfect Evasion (Theoretical)
- Human experts generating every prompt individually
- Unique residential connection per request
- Custom TLS stack
- Canary stripping + complete watermark removal

**Cost**: $3M+/month at scale
**This makes the attack economically unviable** — the cost of evasion exceeds the
cost of legitimate API access to train a model of equivalent capability.

---

## Economic Disincentive Analysis

| Attack Scale | Cost Without Evasion | Cost With Package A Evasion | Package A Break-Even |
|-------------|---------------------|-----------------------------|---------------------|
| 10M requests | $30K (API) | $30K + $50K setup + $8K/mo infra | Never (evasion costs more than API) |
| 100M requests | $300K (API) | $300K + $50K setup + $80K/mo infra | ~18 months |
| 1B requests | $3M (API) | $3M + $50K setup + $800K/mo infra | ~3 months |

**Conclusion**: For campaigns below 100M requests, Package A evasion is not economically
rational.  At nation-state scale (1B+ requests), evasion becomes viable but requires
sustained infrastructure investment that generates additional detection signals
(ASN concentration, payment clustering, DoH usage).

---

## Differential Privacy Implications

See `docs/differential_privacy.md` for an analysis of which IOC bundle fields can
be published to peer providers without violating user privacy guarantees.
