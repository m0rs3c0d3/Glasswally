// glasswally/src/workers/velocity.rs
//
// Velocity worker — timing regularity, RPH, token uniformity, off-hours.
// Runs on every event. O(n) where n = events in 1hr window.

use chrono::Utc;
use serde_json::json;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::{StateStore, W_1HR, W_24HR};

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let window = store.get_window(&event.account_id)?;
    let window = window.read();

    let evs_1h = window.events_in(W_1HR);
    let n = evs_1h.len();
    if n < 5 {
        return Some(DetectionSignal {
            worker: WorkerKind::Velocity, account_id: event.account_id.clone(),
            score: 0.0, confidence: 0.1,
            evidence: vec!["insufficient_data".into()],
            meta: Default::default(), timestamp: Utc::now(),
        });
    }

    let mut score    = 0.0f32;
    let mut evidence = Vec::new();

    // Requests per hour
    let rph = window.rate_per_hour(W_1HR);
    if rph > 200.0      { score += 0.45; evidence.push(format!("extreme_velocity:{:.0}rph", rph)); }
    else if rph > 60.0  { score += 0.25; evidence.push(format!("high_velocity:{:.0}rph", rph)); }

    // Interarrival regularity (CV of gaps)
    let ias = window.interarrivals(W_1HR);
    let regularity = if ias.len() >= 3 {
        let mean = ias.iter().sum::<f64>() / ias.len() as f64;
        let std  = (ias.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / ias.len() as f64).sqrt();
        let cv   = if mean > 0.0 { std / mean } else { 0.0 };
        (1.0 - cv).max(0.0) as f32
    } else { 0.0 };

    if regularity > 0.70      { score += 0.30; evidence.push(format!("scripted_timing:{:.2}", regularity)); }
    else if regularity > 0.50 { score += 0.15; evidence.push(format!("semi_regular:{:.2}", regularity)); }

    // Token count uniformity
    let tokens: Vec<f64> = evs_1h.iter().map(|e| e.token_count as f64).collect();
    if tokens.len() >= 5 {
        let mean = tokens.iter().sum::<f64>() / tokens.len() as f64;
        let std  = (tokens.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / tokens.len() as f64).sqrt();
        let cv   = if mean > 0.0 { std / mean } else { 0.0 };
        if cv < 0.15 { score += 0.15; evidence.push(format!("uniform_tokens:cv={:.3}", cv)); }
    }

    // Off-hours (UTC 00:00–06:00 = CN business hours)
    let evs_24h  = window.events_in(W_24HR);
    let off_count = evs_24h.iter().filter(|e| e.timestamp.format("%H").to_string().parse::<u8>().unwrap_or(12) < 6).count();
    let off_ratio = off_count as f32 / evs_24h.len().max(1) as f32;
    if off_ratio > 0.5 { score += 0.10; evidence.push(format!("off_hours_utc:{:.0}%", off_ratio * 100.0)); }

    let confidence = (n as f32 / 50.0).min(1.0);
    score = (score * (0.5 + 0.5 * confidence)).min(1.0);

    Some(DetectionSignal {
        worker:     WorkerKind::Velocity,
        account_id: event.account_id.clone(),
        score:      (score * 10000.0).round() / 10000.0,
        confidence,
        evidence,
        meta: [
            ("rph".into(), json!(rph)),
            ("regularity".into(), json!(regularity)),
            ("n_1h".into(), json!(n)),
        ].into_iter().collect(),
        timestamp: Utc::now(),
    })
}
