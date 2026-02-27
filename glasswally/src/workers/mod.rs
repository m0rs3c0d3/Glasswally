// Phase 1 (original)
pub mod biometric;
pub mod cot;
pub mod embed;
pub mod fingerprint;
pub mod h2_grpc;
pub mod hydra;
pub mod pivot;
pub mod timing_cluster;
pub mod velocity;
pub mod watermark;
// Phase 1 (new signals)
pub mod asn_classifier;
pub mod refusal_probe;
pub mod role_preamble;
pub mod session_gap;
pub mod token_budget;
// Phase 3
pub mod sequence_model;

use crate::events::{ApiEvent, DetectionSignal};
use crate::state::window::StateStore;

/// Run all 16 detection workers concurrently and collect their signals.
/// Workers returning None (insufficient data / no signal) are silently dropped.
pub async fn run_all(event: &ApiEvent, store: &StateStore) -> Vec<DetectionSignal> {
    let (fp, vel, cot_s, hyd, piv, wm, em, tc, h2, bio, asn, role, gap, tok, ref_p, seq) = tokio::join!(
        fingerprint::analyze(event, store),
        velocity::analyze(event, store),
        cot::analyze(event, store),
        hydra::analyze(event, store),
        pivot::analyze(event, store),
        watermark::analyze(event, store),
        embed::analyze(event, store),
        timing_cluster::analyze(event, store),
        h2_grpc::analyze(event, store),
        biometric::analyze(event, store),
        asn_classifier::analyze(event, store),
        role_preamble::analyze(event, store),
        session_gap::analyze(event, store),
        token_budget::analyze(event, store),
        refusal_probe::analyze(event, store),
        sequence_model::analyze(event, store),
    );

    [
        fp, vel, cot_s, hyd, piv, wm, em, tc, h2, bio, asn, role, gap, tok, ref_p, seq,
    ]
    .into_iter()
    .flatten()
    .collect()
}
