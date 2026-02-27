// glasswally/src/workers/timing_cluster.rs
//
// Cross-account synchronized burst detection.
//
// Key insight: DeepSeek's distributed scraping uses synchronized load
// balancers that fire multiple accounts at coordinated intervals.
// Individual account velocity looks normal (~50 RPH), but 15 accounts
// all fire within the same second on a repeating cadence.
//
// This worker looks at global 1-second timing buckets:
//   - Count distinct accounts firing in each 1-second window
//   - N ≥ MIN_BURST_SIZE accounts in same bucket → synchronized burst
//   - Recurring bursts at regular intervals → scripted coordination
//
// This signal is impossible to fake without either:
//   a) Introducing per-account random delays → reduces throughput 30–50%
//   b) Fully decentralizing the scheduler → operational complexity × N
//
// Both have significant economic cost that degrades the extraction ROI.

use chrono::Utc;
use serde_json::json;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

const MIN_BURST_SIZE:   usize = 5;   // accounts per 1s window to fire signal
const STRONG_BURST:     usize = 12;  // accounts per window for high confidence
const RECUR_MIN_BURSTS: usize = 3;   // recurring bursts needed to confirm cadence
const CADENCE_LOOKBACK: u64   = 300; // seconds of history to scan for cadence

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let bucket = event.timestamp.timestamp() as u64;

    // StateStore.ingest() already recorded this account in the bucket.
    // We just query here — no side effects in the worker.
    let n_concurrent = store.accounts_in_bucket(bucket);

    if n_concurrent < MIN_BURST_SIZE { return None; }

    let mut score    = 0.0f32;
    let mut evidence = Vec::new();

    // ── Current bucket burst ──────────────────────────────────────────────────
    let burst_frac = (n_concurrent - MIN_BURST_SIZE) as f32
        / (STRONG_BURST - MIN_BURST_SIZE) as f32;
    score += (burst_frac * 0.50).min(0.50);
    evidence.push(format!("sync_burst:{}_accounts_in_1s", n_concurrent));

    // ── Recurring cadence scan ────────────────────────────────────────────────
    // Look back CADENCE_LOOKBACK seconds for earlier bursts.
    let burst_times: Vec<u64> = (1..=CADENCE_LOOKBACK)
        .filter_map(|i| {
            let b = bucket.saturating_sub(i);
            if store.accounts_in_bucket(b) >= MIN_BURST_SIZE { Some(b) } else { None }
        })
        .collect();

    let n_prior_bursts = burst_times.len();
    if n_prior_bursts >= RECUR_MIN_BURSTS {
        score += 0.30;
        evidence.push(format!("recurring_sync:{}_bursts_in_{}s", n_prior_bursts, CADENCE_LOOKBACK));

        // Measure cadence regularity (low CV = clock-driven)
        if burst_times.len() >= 3 {
            let gaps: Vec<f64> = burst_times.windows(2)
                .map(|w| (w[0] - w[1]) as f64)   // descending timestamps → positive gaps
                .collect();
            let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
            let std  = (gaps.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
                        / gaps.len() as f64).sqrt();
            let cv   = if mean > 1.0 { std / mean } else { 1.0 };

            if cv < 0.15 {
                score += 0.20;
                evidence.push(format!("clock_cadence:{:.0}s_interval_cv={:.3}", mean, cv));
            } else if cv < 0.35 {
                score += 0.10;
                evidence.push(format!("semi_regular_cadence:{:.0}s_cv={:.3}", mean, cv));
            }
        }
    }

    let confidence = (n_concurrent as f32 / STRONG_BURST as f32).min(1.0);

    Some(DetectionSignal {
        worker:     WorkerKind::TimingCluster,
        account_id: event.account_id.clone(),
        score:      score.min(1.0),
        confidence,
        evidence,
        meta: [
            ("n_concurrent".into(),   json!(n_concurrent)),
            ("bucket_ts".into(),      json!(bucket)),
            ("n_prior_bursts".into(), json!(n_prior_bursts)),
        ].into_iter().collect(),
        timestamp: Utc::now(),
    })
}
