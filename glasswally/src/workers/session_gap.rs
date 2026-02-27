// glasswally/src/workers/session_gap.rs
//
// Inter-session gap analysis — Phase 1 signal.
//
// Automated distillation jobs are typically scheduled by cron or a task scheduler.
// This produces highly regular inter-session gaps (e.g., exactly 3600s ± a few
// seconds for a job that runs every hour).  Human users have irregular gaps.
//
// Definitions:
//   session    — a burst of requests with < SESSION_BREAK_SECS between events.
//   inter-session gap — time between the last event of one session and the first
//                       event of the next session.
//
// Signals:
//   cron_regularity     — CV of inter-session gaps < 0.08 (very regular)
//                         Score depends on dominant gap interval.
//   burst_uniformity    — session lengths (request count) are uniform (CV < 0.10)
//                         combined with cron_regularity → near-certain automation
//   too_many_sessions   — >20 distinct sessions in 24h → batch job cadence
//
// Minimum sessions required: 4

use std::collections::HashMap;

use chrono::Utc;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

const SESSION_BREAK_SECS: i64 = 120; // gap ≥ 2 min → new session
const MIN_SESSIONS: usize = 4;

/// Split a chronologically-sorted sequence of Unix timestamps into sessions.
/// Returns (session_start, session_end, n_requests) per session.
fn sessions_from_timestamps(ts: &[i64]) -> Vec<(i64, i64, usize)> {
    if ts.is_empty() {
        return vec![];
    }
    let mut out = Vec::new();
    let mut start = ts[0];
    let mut prev = ts[0];
    let mut count = 1usize;

    for &t in &ts[1..] {
        if t - prev >= SESSION_BREAK_SECS {
            out.push((start, prev, count));
            start = t;
            count = 1;
        } else {
            count += 1;
        }
        prev = t;
    }
    out.push((start, prev, count));
    out
}

fn mean_and_cv(vals: &[f64]) -> (f64, f64) {
    if vals.is_empty() {
        return (0.0, 0.0);
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    if mean == 0.0 {
        return (0.0, 0.0);
    }
    let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
    (mean, var.sqrt() / mean)
}

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let window = store.get_window(&event.account_id)?;

    let timestamps: Vec<i64> = {
        let w = window.read();
        let mut ts: Vec<i64> = w.events.iter().map(|e| e.timestamp.timestamp()).collect();
        ts.sort_unstable();
        ts
    };

    if timestamps.len() < 8 {
        return None;
    }

    let sessions = sessions_from_timestamps(&timestamps);
    if sessions.len() < MIN_SESSIONS {
        return None;
    }

    // Inter-session gaps (seconds) between consecutive sessions.
    let gaps: Vec<f64> = sessions
        .windows(2)
        .map(|w| (w[1].0 - w[0].1) as f64)
        .filter(|&g| g > 0.0)
        .collect();

    if gaps.is_empty() {
        return None;
    }

    let (mean_gap, gap_cv) = mean_and_cv(&gaps);

    // Session sizes (request count).
    let session_sizes: Vec<f64> = sessions.iter().map(|s| s.2 as f64).collect();
    let (_, size_cv) = mean_and_cv(&session_sizes);

    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // ── 1. Cron regularity ────────────────────────────────────────────────────
    if gap_cv < 0.05 {
        score += 0.55;
        evidence.push(format!(
            "cron_regularity:gap={:.0}s_cv={:.3}",
            mean_gap, gap_cv
        ));
    } else if gap_cv < 0.08 {
        score += 0.40;
        evidence.push(format!(
            "cron_regularity:gap={:.0}s_cv={:.3}",
            mean_gap, gap_cv
        ));
    } else if gap_cv < 0.15 {
        score += 0.20;
        evidence.push(format!(
            "semi_regular_gaps:gap={:.0}s_cv={:.3}",
            mean_gap, gap_cv
        ));
    }

    // ── 2. Burst uniformity (compound signal) ─────────────────────────────────
    if size_cv < 0.10 && gap_cv < 0.15 {
        score += 0.25;
        evidence.push(format!("burst_uniformity:size_cv={:.3}", size_cv));
    }

    // ── 3. Session count density ───────────────────────────────────────────────
    if sessions.len() > 20 {
        score += 0.10;
        evidence.push(format!("high_session_count:{}", sessions.len()));
    }

    if score < 0.15 {
        return None;
    }

    let confidence = if gap_cv < 0.05 {
        0.88
    } else if gap_cv < 0.08 {
        0.75
    } else {
        0.55
    };

    let mut meta = HashMap::new();
    meta.insert(
        "n_sessions".to_string(),
        serde_json::Value::Number(serde_json::Number::from(sessions.len() as u64)),
    );
    meta.insert(
        "mean_gap_secs".to_string(),
        serde_json::json!(mean_gap.round() as i64),
    );
    meta.insert(
        "gap_cv".to_string(),
        serde_json::json!((gap_cv * 1000.0).round() / 1000.0),
    );
    meta.insert(
        "session_size_cv".to_string(),
        serde_json::json!((size_cv * 1000.0).round() / 1000.0),
    );

    Some(DetectionSignal {
        worker: WorkerKind::SessionGap,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence,
        evidence,
        meta,
        timestamp: Utc::now(),
    })
}
