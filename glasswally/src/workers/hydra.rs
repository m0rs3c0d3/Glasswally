// glasswally/src/workers/hydra.rs
//
// Hydra cluster worker — scores accounts based on cluster membership.
// The cluster graph is maintained by StateStore; this worker just queries it.

use chrono::Utc;
use serde_json::json;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let cluster_id = store.get_cluster(&event.account_id)?;
    let members    = store.cluster_members(cluster_id);
    let n          = members.len();

    if n < 3 {
        return Some(DetectionSignal {
            worker: WorkerKind::Hydra, account_id: event.account_id.clone(),
            score: 0.0, confidence: 0.2,
            evidence: vec!["small_cluster".into()],
            meta: Default::default(), timestamp: Utc::now(),
        });
    }

    let mut score    = 0.0f32;
    let mut evidence = Vec::new();

    // Cluster size
    let size_score = (n as f32 / 25.0).min(1.0) * 0.40;
    score += size_score;
    evidence.push(format!("cluster_{}_size:{}", cluster_id, n));

    // Shared payment methods across cluster
    let mut shared_payments = std::collections::HashSet::new();
    let mut shared_subnets  = std::collections::HashSet::new();
    let mut all_countries   = std::collections::HashSet::new();
    let mut total_requests  = 0usize;

    for member_id in &members {
        if let Some(w) = store.get_window(member_id) {
            let w = w.read();
            shared_payments.extend(w.payment_hashes.iter().cloned());
            shared_subnets.extend(w.subnets());
            all_countries.extend(w.country_codes.iter().cloned());
            total_requests += w.events.len();
        }
    }

    if !shared_payments.is_empty() {
        score += (shared_payments.len() as f32 * 0.07).min(0.35);
        evidence.push(format!("shared_payments:{}", shared_payments.len()));
    }
    if !shared_subnets.is_empty() {
        score += (shared_subnets.len() as f32 * 0.03).min(0.15);
        evidence.push(format!("shared_subnets:{}", shared_subnets.len()));
    }
    if all_countries.contains("CN") {
        score += 0.10;
        evidence.push("restricted_geo:CN".into());
    }

    let confidence = (total_requests as f32 / 100.0).min(1.0);
    score = score.min(1.0);

    Some(DetectionSignal {
        worker:     WorkerKind::Hydra,
        account_id: event.account_id.clone(),
        score,
        confidence,
        evidence,
        meta: [
            ("cluster_id".into(),    json!(cluster_id)),
            ("cluster_size".into(),  json!(n)),
            ("total_requests".into(),json!(total_requests)),
        ].into_iter().collect(),
        timestamp: Utc::now(),
    })
}
