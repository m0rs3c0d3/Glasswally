// glasswally/src/engine/fusion.rs
//
// Weighted signal fusion with geo uplift + cluster floor raise.
//
// Weight distribution across 10 workers (sum = 1.00):
//   Fingerprint   0.20  — JA3 + JA3S + header entropy (highest precision)
//   Velocity      0.13  — RPH / timing (complemented by TimingCluster)
//   Cot           0.12  — Aho-Corasick patterns (complemented by Embed)
//   Embed         0.10  — semantic similarity (catches CoT paraphrases)
//   Hydra         0.11  — cluster graph scoring
//   TimingCluster 0.09  — cross-account synchronized bursts
//   H2Grpc        0.07  — HTTP/2 SETTINGS + gRPC fingerprinting
//   Pivot         0.07  — coordinated model switch
//   Biometric     0.06  — prompt sequence entropy
//   Watermark     0.05  — watermark probe / ZW character detection
//
// Original 5-worker system: Fingerprint(30) + Velocity(23) + Cot(23) + Hydra(14) + Pivot(10)
// The added signals are redistributed proportionally while preserving the
// relative ordering of precision.

use chrono::Utc;
use dashmap::DashMap;
use std::collections::HashMap;

use crate::events::{ActionKind, ApiEvent, DetectionSignal, RiskDecision, RiskTier, WorkerKind};
use crate::state::window::StateStore;

// Signal weights — must sum to 1.0
const WEIGHTS: &[(WorkerKind, f32)] = &[
    (WorkerKind::Fingerprint,   0.20),
    (WorkerKind::Velocity,      0.13),
    (WorkerKind::Cot,           0.12),
    (WorkerKind::Embed,         0.10),
    (WorkerKind::Hydra,         0.11),
    (WorkerKind::TimingCluster, 0.09),
    (WorkerKind::H2Grpc,        0.07),
    (WorkerKind::Pivot,         0.07),
    (WorkerKind::Biometric,     0.06),
    (WorkerKind::Watermark,     0.05),
];

const CRITICAL: f32 = 0.72;
const HIGH:     f32 = 0.55;
const MEDIUM:   f32 = 0.35;
const COOLDOWN: i64 = 600; // seconds before re-alerting same account

pub struct FusionEngine {
    last_alert: DashMap<String, chrono::DateTime<Utc>>,
    suspended:  DashMap<String, bool>,
}

impl FusionEngine {
    pub fn new() -> Self {
        Self { last_alert: DashMap::new(), suspended: DashMap::new() }
    }

    pub fn fuse(
        &self,
        event:   &ApiEvent,
        store:   &StateStore,
        signals: &[DetectionSignal],
    ) -> Option<RiskDecision> {
        if signals.is_empty() { return None; }

        let sig_map: HashMap<WorkerKind, &DetectionSignal> =
            signals.iter().map(|s| (s.worker, s)).collect();

        let mut composite  = 0.0f32;
        let mut sig_scores: HashMap<String, f32> = HashMap::new();

        for (worker, weight) in WEIGHTS {
            if let Some(s) = sig_map.get(worker) {
                let effective = s.score * (0.4 + 0.6 * s.confidence);
                composite += effective * weight;
                sig_scores.insert(worker.to_string(), s.score);
            }
        }

        // Geo uplift — CN access raises composite 30%
        if event.country_code == "CN" {
            composite = (composite * 1.30).min(1.0);
        }

        // Cluster floor — being in a large cluster adds 8 points
        if let Some(cid) = store.get_cluster(&event.account_id) {
            if store.cluster_members(cid).len() >= 5 {
                composite = (composite + 0.08).min(1.0);
            }
        }

        composite = (composite * 10000.0).round() / 10000.0;
        if composite < MEDIUM { return None; }

        let (tier, action) = if composite >= CRITICAL {
            (RiskTier::Critical, ActionKind::SuspendAccount)
        } else if composite >= HIGH {
            // High tier: inject canary + flag for review
            (RiskTier::High, ActionKind::InjectCanary)
        } else {
            (RiskTier::Medium, ActionKind::RateLimit)
        };

        let top_evidence: Vec<String> = signals.iter()
            .flat_map(|s| s.evidence.iter().cloned())
            .filter(|e| !["cached", "no_cluster", "insufficient_data", "small_cluster",
                          "account_watermarked"].contains(&e.as_str()))
            .take(10).collect();

        let window    = store.get_window(&event.account_id);
        let n_reqs    = window.as_ref().map(|w| w.read().events.len()).unwrap_or(0);
        let countries = window.map(|w| w.read().country_codes.iter().cloned().collect())
                              .unwrap_or_default();

        Some(RiskDecision {
            account_id:      event.account_id.clone(),
            composite_score: composite,
            tier,
            signal_scores:   sig_scores,
            top_evidence,
            country_codes:   countries,
            cluster_id:      store.get_cluster(&event.account_id),
            n_requests_seen: n_reqs,
            action,
            timestamp:       Utc::now(),
            ground_truth:    event.campaign_label.clone(),
        })
    }

    pub fn should_alert(&self, account_id: &str) -> bool {
        if self.suspended.get(account_id).map(|s| *s).unwrap_or(false) { return false; }
        self.last_alert.get(account_id)
            .map(|t| (Utc::now() - *t).num_seconds() >= COOLDOWN)
            .unwrap_or(true)
    }

    pub fn record_alert(&self, account_id: &str, suspend: bool) {
        self.last_alert.insert(account_id.to_string(), Utc::now());
        if suspend { self.suspended.insert(account_id.to_string(), true); }
    }
}

impl Default for FusionEngine { fn default() -> Self { Self::new() } }
