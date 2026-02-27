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

use crate::events::{ApiEvent, DetectionSignal};
use crate::state::window::StateStore;

/// Run all detection workers concurrently and collect their signals.
/// Workers returning None (insufficient data / no signal) are silently dropped.
pub async fn run_all(event: &ApiEvent, store: &StateStore) -> Vec<DetectionSignal> {
    let (fp, vel, cot_s, hyd, piv, wm, em, tc, h2, bio) = tokio::join!(
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
    );

    [fp, vel, cot_s, hyd, piv, wm, em, tc, h2, bio]
        .into_iter()
        .flatten()
        .collect()
}
