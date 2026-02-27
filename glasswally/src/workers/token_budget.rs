// glasswally/src/workers/token_budget.rs
//
// Token budget probing — Phase 1 signal.
//
// Distillation campaigns systematically vary max_tokens to:
//   A. Discover the model's maximum response length (capability probing)
//   B. Always request the maximum to get the fullest training signal possible
//   C. Sweep powers-of-two to map response length distributions
//
// Two complementary signals:
//
//   1. GREEDY BUDGET — account repeatedly requests max_tokens at or near the
//      hard limit (e.g., 4096, 8192, 16384, 32768). Legitimate users rarely
//      need maximum context every request; systematic extraction always does.
//
//   2. SYSTEMATIC SWEEP — the account's max_tokens sequence follows a geometric
//      or arithmetic progression (1, 4, 16, 64, 256 ... or 100, 200, 400 ...).
//      This is a classic capability boundary probe.
//
// Score contributions:
//   greedy_budget:      +0.30  (≥70% of requests at ≥90% of likely model max)
//   systematic_sweep:   +0.45  (geometric/arithmetic progression detected)
//   high_median_tokens: +0.10  (median max_tokens > 2000)

use std::collections::HashMap;

use chrono::Utc;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

/// Common model maximum context sizes (token counts).
const MODEL_MAXIMA: &[u32] = &[1024, 2048, 4096, 8192, 16384, 32768, 65536, 128000, 200000];

/// How close to the model maximum counts as "greedy" (90%).
const GREEDY_THRESHOLD: f32 = 0.90;

/// Minimum requests needed before emitting this signal.
const MIN_SAMPLES: usize = 6;

fn nearest_model_max(v: u32) -> u32 {
    *MODEL_MAXIMA
        .iter()
        .min_by_key(|&&m| (m as i64 - v as i64).unsigned_abs())
        .unwrap_or(&4096)
}

/// Detect if a sorted sequence of values follows a geometric progression (ratio ~constant).
fn is_geometric(vals: &[u32]) -> bool {
    if vals.len() < 4 {
        return false;
    }
    let ratios: Vec<f64> = vals
        .windows(2)
        .filter(|w| w[0] > 0)
        .map(|w| w[1] as f64 / w[0] as f64)
        .collect();
    if ratios.is_empty() {
        return false;
    }
    let mean_r = ratios.iter().sum::<f64>() / ratios.len() as f64;
    if mean_r < 1.5 {
        return false;
    } // not growing fast enough
    let cv = {
        let var = ratios.iter().map(|r| (r - mean_r).powi(2)).sum::<f64>() / ratios.len() as f64;
        var.sqrt() / mean_r
    };
    cv < 0.25 // consistent ratio
}

/// Detect if a sorted sequence of values follows an arithmetic progression (diff ~constant).
fn is_arithmetic(vals: &[u32]) -> bool {
    if vals.len() < 4 {
        return false;
    }
    let diffs: Vec<i64> = vals.windows(2).map(|w| w[1] as i64 - w[0] as i64).collect();
    let mean_d = diffs.iter().sum::<i64>() as f64 / diffs.len() as f64;
    if mean_d <= 0.0 {
        return false;
    }
    let cv = {
        let var = diffs
            .iter()
            .map(|d| (*d as f64 - mean_d).powi(2))
            .sum::<f64>()
            / diffs.len() as f64;
        var.sqrt() / mean_d
    };
    cv < 0.20
}

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    // Only meaningful when max_tokens is present in the API request.
    let _current_max = event.max_tokens?;

    let window = store.get_window(&event.account_id)?;
    let token_seq: Vec<u32> = {
        let w = window.read();
        w.events.iter().filter_map(|e| e.max_tokens).collect()
    };

    if token_seq.len() < MIN_SAMPLES {
        return None;
    }

    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // ── 1. Greedy budget detection ────────────────────────────────────────────
    let greedy_count = token_seq
        .iter()
        .filter(|&&t| {
            let model_max = nearest_model_max(t);
            t as f32 / model_max as f32 >= GREEDY_THRESHOLD
        })
        .count();

    let greedy_frac = greedy_count as f32 / token_seq.len() as f32;
    if greedy_frac >= 0.70 {
        score += 0.30;
        evidence.push(format!(
            "greedy_budget:{:.0}%_requests_at_max",
            greedy_frac * 100.0
        ));
    }

    // ── 2. Systematic sweep detection ─────────────────────────────────────────
    let mut sorted = token_seq.clone();
    sorted.sort_unstable();
    sorted.dedup();

    if is_geometric(&sorted) {
        score += 0.45;
        evidence.push(format!("geometric_sweep:{}_distinct_values", sorted.len()));
    } else if is_arithmetic(&sorted) {
        score += 0.35;
        evidence.push(format!("arithmetic_sweep:{}_distinct_values", sorted.len()));
    }

    // ── 3. High median ────────────────────────────────────────────────────────
    let mut sorted_all = token_seq.clone();
    sorted_all.sort_unstable();
    let median = sorted_all[sorted_all.len() / 2];
    if median > 2000 {
        score += 0.10;
        evidence.push(format!("high_median_tokens:{}", median));
    }

    if score < 0.20 {
        return None;
    }

    let confidence = if evidence.len() >= 2 { 0.82 } else { 0.60 };

    let mut meta = HashMap::new();
    meta.insert(
        "n_samples".to_string(),
        serde_json::Value::Number(serde_json::Number::from(token_seq.len() as u64)),
    );
    meta.insert(
        "median_max_tokens".to_string(),
        serde_json::Value::Number(serde_json::Number::from(median as u64)),
    );
    meta.insert(
        "distinct_values".to_string(),
        serde_json::Value::Number(serde_json::Number::from(sorted.len() as u64)),
    );

    Some(DetectionSignal {
        worker: WorkerKind::TokenBudget,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence,
        evidence,
        meta,
        timestamp: Utc::now(),
    })
}
