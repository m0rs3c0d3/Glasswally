pub mod cot;
pub mod fingerprint;
pub mod hydra;
pub mod pivot;
pub mod velocity;

use crate::events::{ApiEvent, DetectionSignal};
use crate::state::window::StateStore;

/// Run all detection workers concurrently and collect their signals.
pub async fn run_all(event: &ApiEvent, store: &StateStore) -> Vec<DetectionSignal> {
    let (fp, vel, cot_s, hyd, piv) = tokio::join!(
        fingerprint::run(event, store),
        velocity::run(event, store),
        cot::run(event, store),
        hydra::run(event, store),
        pivot::run(event, store),
    );

    let mut signals = Vec::new();
    signals.extend(fp);
    signals.extend(vel);
    signals.extend(cot_s);
    signals.extend(hyd);
    signals.extend(piv);
    signals
}
