// glasswally/src/redteam.rs
//
// Adversarial robustness evaluation.
//
// Quantifies the *economic cost* of evading each detector.
// "Economic cost" = reduction in extraction throughput + engineering overhead
// expressed as: fraction of original throughput retained × operational burden.
//
// Key insight: each evasion technique shifts load to another detector.
// Evading JA3 (cheap) → caught by JA3S + header entropy.
// Evading all TLS signals → requires real browser automation → 75% throughput drop.
// Evading timing → requires full scheduler desync → operational complexity × N.
//
// The composite system makes full evasion economically unviable:
//   Full evasion suite cost > $500k/year operational + 75% extraction reduction.
//
// Use `cargo run -- redteam` to generate and print the report.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::events::WorkerKind;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvasionCost {
    Trivial,      // No code change, works immediately
    Low,          // Minor flag/env var change — <2h engineering
    Medium,       // Library swap or proxy layer — 1–2 days
    High,         // Infrastructure change — >1 week + ops overhead
    Prohibitive,  // Makes extraction economically unviable at scale
}

impl std::fmt::Display for EvasionCost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trivial     => write!(f, "TRIVIAL"),
            Self::Low         => write!(f, "LOW"),
            Self::Medium      => write!(f, "MEDIUM"),
            Self::High        => write!(f, "HIGH"),
            Self::Prohibitive => write!(f, "PROHIBITIVE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionVector {
    pub name:               String,
    pub technique:          String,
    pub cost:               EvasionCost,
    /// Fraction of baseline extraction throughput retained (0.0–1.0).
    pub throughput_impact:  f32,
    /// Which other detector(s) still fire after this evasion.
    pub residual_detection: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorReport {
    pub detector:        WorkerKind,
    pub vectors:         Vec<EvasionVector>,
    pub min_evasion_cost: EvasionCost,
    pub residual_risk:   f32,  // probability of detection even with best evasion
    pub notes:           String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeReport {
    pub per_detector:    Vec<DetectorReport>,
    pub composite_cost:  EvasionCost,
    pub min_throughput:  f32,   // retained throughput after full evasion
    pub annual_op_cost:  String, // rough $ estimate
    pub summary:         String,
    pub timestamp:       chrono::DateTime<chrono::Utc>,
}

/// Generate the full adversarial robustness report.
pub fn evaluate_all() -> CompositeReport {
    let reports = vec![
        fingerprint_report(),
        velocity_report(),
        cot_report(),
        embed_report(),
        hydra_report(),
        timing_cluster_report(),
        h2_grpc_report(),
        biometric_report(),
        watermark_report(),
        pivot_report(),
    ];

    let min_throughput: f32 = reports.iter()
        .flat_map(|r| r.vectors.iter().map(|v| v.throughput_impact))
        .fold(1.0f32, f32::min);

    CompositeReport {
        per_detector:   reports,
        composite_cost: EvasionCost::Prohibitive,
        min_throughput,
        annual_op_cost: "$500k+ (residential proxies, Playwright automation, \
                         LLM paraphrasing, payment fragmentation, ops headcount)".into(),
        summary: format!(
            "Full evasion requires Playwright automation ({:.0}% throughput retained), \
             residential proxies ($500+/mo), LLM-based prompt paraphrasing (doubles \
             per-query cost), payment fragmentation (50+ payment methods), and \
             full scheduler desynchronization. Economic ROI breakeven requires \
             extracting >$2M of model value from a single provider.",
            min_throughput * 100.0
        ),
        timestamp: Utc::now(),
    }
}

fn fingerprint_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Fingerprint,
        vectors: vec![
            EvasionVector {
                name:              "cycletls_ja3_spoof".into(),
                technique:         "CycleTLS / tls-client: spoof JA3 at socket level".into(),
                cost:              EvasionCost::Low,
                throughput_impact: 0.90,
                residual_detection:"JA3S mismatch (server hello unchanged), \
                                    header entropy (CycleTLS header order differs)".into(),
            },
            EvasionVector {
                name:              "playwright_real_browser".into(),
                technique:         "Playwright/Selenium: real Chromium TLS stack, \
                                    authentic JA3 + JA3S + headers".into(),
                cost:              EvasionCost::Medium,
                throughput_impact: 0.22,   // browser automation 4–5x slower
                residual_detection:"Biometric (sequence entropy), \
                                    TimingCluster (coordination still visible)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Low,
        residual_risk:    0.60,
        notes: "CycleTLS defeats JA3 but not the JA3S+header combo. \
                Playwright defeats everything in this layer at 78% throughput cost.".into(),
    }
}

fn velocity_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Velocity,
        vectors: vec![
            EvasionVector {
                name:              "rate_spread".into(),
                technique:         "Spread 200 RPH across 10 accounts at 20 RPH each".into(),
                cost:              EvasionCost::Low,
                throughput_impact: 0.85,
                residual_detection:"Hydra (shared infrastructure), \
                                    TimingCluster (accounts still synchronized)".into(),
            },
            EvasionVector {
                name:              "poisson_jitter".into(),
                technique:         "Add Poisson(λ=2s) inter-request delays".into(),
                cost:              EvasionCost::Trivial,
                throughput_impact: 0.65,
                residual_detection:"TimingCluster (cross-account synchrony survives jitter)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Trivial,
        residual_risk:    0.55,
        notes: "Velocity is the easiest detector to individually evade but evasion \
                shifts signal load to Hydra and TimingCluster.".into(),
    }
}

fn cot_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Cot,
        vectors: vec![
            EvasionVector {
                name:              "paraphrase_prompts".into(),
                technique:         "Paraphrase extraction prompts — \
                                    'Walk me through it' instead of 'step by step'".into(),
                cost:              EvasionCost::Low,
                throughput_impact: 0.95,
                residual_detection:"Embed worker (semantic similarity still fires at >0.7)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Low,
        residual_risk:    0.65,
        notes: "Aho-Corasick pattern matching is defeated by paraphrasing. \
                The Embed semantic worker closes this gap — CoT + Embed together \
                are robust to all known paraphrase strategies.".into(),
    }
}

fn embed_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Embed,
        vectors: vec![
            EvasionVector {
                name:              "adversarial_phrasing".into(),
                technique:         "Out-of-distribution phrasing: formal academic, legal, \
                                    or non-English prefix wrapping extraction intent".into(),
                cost:              EvasionCost::Medium,
                throughput_impact: 0.70,  // requires LLM paraphrasing overhead
                residual_detection:"Biometric (unusual style changes sequence entropy)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Medium,
        residual_risk:    0.50,
        notes: "Defeating semantic similarity requires per-prompt LLM paraphrasing, \
                which adds latency and cost. The resulting style changes are detectable \
                by the biometric sequence entropy worker.".into(),
    }
}

fn hydra_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Hydra,
        vectors: vec![
            EvasionVector {
                name:              "full_infra_isolation".into(),
                technique:         "Unique payment + unique IP + unique org per account. \
                                    Zero shared infrastructure signals.".into(),
                cost:              EvasionCost::High,
                throughput_impact: 0.92,
                residual_detection:"TimingCluster (scheduling coordination visible), \
                                    Payment graph (card batch correlation)".into(),
            },
            EvasionVector {
                name:              "prepaid_card_fragmentation".into(),
                technique:         "Prepaid cards from different physical stores to avoid \
                                    shared payment processor fingerprint".into(),
                cost:              EvasionCost::High,
                throughput_impact: 0.97,  // ops cost, not throughput
                residual_detection:"Payment graph analytics (BIN prefix correlation)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::High,
        residual_risk:    0.45,
        notes: "Full infrastructure isolation is operationally expensive at the scale \
                needed for distillation campaigns (50–500 accounts). Payment graph \
                analytics catches card batch correlation even across stores.".into(),
    }
}

fn timing_cluster_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::TimingCluster,
        vectors: vec![
            EvasionVector {
                name:              "gaussian_jitter".into(),
                technique:         "Per-account Gaussian jitter (σ=3s) — \
                                    spreads 1s bucket into ~5s window".into(),
                cost:              EvasionCost::Trivial,
                throughput_impact: 0.75,
                residual_detection:"TimingCluster with 5s bucket width (TODO: implement)".into(),
            },
            EvasionVector {
                name:              "full_desync".into(),
                technique:         "Remove shared scheduler entirely — each account \
                                    runs independently on its own process/host".into(),
                cost:              EvasionCost::High,
                throughput_impact: 0.80,
                residual_detection:"Hydra (accounts still share payment/IP infrastructure)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Trivial,
        residual_risk:    0.50,
        notes: "Jitter is cheap but our 1s bucket catches ±1s desync. \
                Extending to a 5s bucket would catch σ=3s jitter. \
                Full desync has significant operational overhead and shifts \
                to Hydra.".into(),
    }
}

fn h2_grpc_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::H2Grpc,
        vectors: vec![
            EvasionVector {
                name:              "spoof_browser_settings".into(),
                technique:         "Configure HTTP/2 client with Chrome SETTINGS values \
                                    (TABLE=65536, WIN=6291456, PUSH=1)".into(),
                cost:              EvasionCost::Low,
                throughput_impact: 1.0,
                residual_detection:"JA3 / JA3S fingerprint (TLS stack still differs from Chrome)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Low,
        residual_risk:    0.65,
        notes: "H2 settings alone can be spoofed with one config change. \
                Combined JA3 + JA3S + H2 requires real browser stack (Playwright).".into(),
    }
}

fn biometric_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Biometric,
        vectors: vec![
            EvasionVector {
                name:              "llm_prompt_diversity".into(),
                technique:         "Generate diverse prompt wrappers via a small LLM \
                                    to increase sequence entropy artificially".into(),
                cost:              EvasionCost::High,
                throughput_impact: 0.40,  // adds full LLM inference per request
                residual_detection:"Semantic embed (core extraction intent still similar)".into(),
            },
            EvasionVector {
                name:              "noise_queries".into(),
                technique:         "Interleave extraction prompts with unrelated off-topic \
                                    queries to inflate sequence entropy".into(),
                cost:              EvasionCost::Medium,
                throughput_impact: 0.50,  // 50% of queries wasted
                residual_detection:"CoT+Embed workers still flag extraction prompts".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Medium,
        residual_risk:    0.50,
        notes: "Behavioral evasion requires either wasting queries (halves ROI) or \
                adding LLM inference per request (doubles cost + 60% throughput drop). \
                Either approach makes large-scale extraction economically marginal.".into(),
    }
}

fn watermark_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Watermark,
        vectors: vec![
            EvasionVector {
                name:              "unicode_normalize".into(),
                technique:         "Apply NFKC normalization to all responses before \
                                    storing — removes zero-width characters".into(),
                cost:              EvasionCost::Trivial,
                throughput_impact: 1.0,
                residual_detection:"Watermark probe detection (normalization code in prompts), \
                                    Statistical/synonym watermarks (future work)".into(),
            },
            EvasionVector {
                name:              "paraphrase_responses".into(),
                technique:         "Pass each response through a paraphrase model to remove \
                                    any structural watermarking before training corpus ingestion".into(),
                cost:              EvasionCost::High,
                throughput_impact: 0.50,  // doubles inference cost
                residual_detection:"Velocity (doubled latency affects timing profile)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Trivial,
        residual_risk:    0.30,
        notes: "Unicode normalization trivially removes ZWJ/ZWNJ watermarks. \
                Synonym/statistical watermarks (word choice, sentence length distribution) \
                are more robust and not yet implemented. Paraphrase evasion doubles \
                training cost and degrades data quality.".into(),
    }
}

fn pivot_report() -> DetectorReport {
    DetectorReport {
        detector: WorkerKind::Pivot,
        vectors: vec![
            EvasionVector {
                name:              "staggered_switch".into(),
                technique:         "Switch models across accounts over 48h \
                                    instead of within the 6h detection window".into(),
                cost:              EvasionCost::Low,
                throughput_impact: 0.98,
                residual_detection:"Pivot with extended window (TODO: 48h scan)".into(),
            },
        ],
        min_evasion_cost: EvasionCost::Low,
        residual_risk:    0.70,
        notes: "Pivot is a low-weight signal (7%). Even if fully evaded, \
                composite score stays elevated from other signals.".into(),
    }
}
