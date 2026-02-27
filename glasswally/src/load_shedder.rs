// glasswally/src/load_shedder.rs
//
// Graceful load shedding — Phase 2.
//
// At high request volumes (e.g., a DDoS-adjacent load burst or genuine traffic
// spike) the detection pipeline must shed low-value work rather than building
// an unbounded queue or crashing.
//
// Shedding policy (priority order — lower number = higher priority):
//   P0: Accounts already flagged High or Critical — always process
//   P1: Accounts in a known cluster — process if queue depth < HIGH_WATER
//   P2: Accounts with existing window history — process if queue depth < MID_WATER
//   P3: New accounts (no history) — process if queue depth < LOW_WATER
//   DROP: Everything else when queue > HIGH_WATER
//
// The shedder sits in front of the tokio event channel.  It does not affect
// the event source (eBPF / tail mode) — events are accepted and immediately
// classified; only pipeline processing is skipped for P3 events under load.
//
// Metrics:
//   shed_total   — cumulative events shed
//   accepted_p0  — accepted as P0
//   queue_depth  — current async channel depth estimate

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::events::ApiEvent;
use crate::state::window::StateStore;

// ── Watermarks ────────────────────────────────────────────────────────────────
const LOW_WATER:  usize = 4_096;
const MID_WATER:  usize = 8_192;
const HIGH_WATER: usize = 12_288;

// ── Priority levels ───────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority { P0Critical, P1Cluster, P2Known, P3New }

pub struct LoadShedder {
    pub shed_total:  AtomicU64,
    pub accepted_p0: AtomicU64,
    pub accepted_p1: AtomicU64,
    pub accepted_p2: AtomicU64,
    pub accepted_p3: AtomicU64,
    store: Arc<StateStore>,
}

impl LoadShedder {
    pub fn new(store: Arc<StateStore>) -> Arc<Self> {
        Arc::new(Self {
            shed_total:  AtomicU64::new(0),
            accepted_p0: AtomicU64::new(0),
            accepted_p1: AtomicU64::new(0),
            accepted_p2: AtomicU64::new(0),
            accepted_p3: AtomicU64::new(0),
            store,
        })
    }

    /// Returns true if this event should be processed; false if shed.
    /// `queue_depth` should be the current mpsc channel buffer level.
    pub fn should_process(&self, event: &ApiEvent, queue_depth: usize) -> bool {
        let priority = self.classify(event);

        let accept = match priority {
            Priority::P0Critical => true,
            Priority::P1Cluster  => queue_depth < HIGH_WATER,
            Priority::P2Known    => queue_depth < MID_WATER,
            Priority::P3New      => queue_depth < LOW_WATER,
        };

        if accept {
            match priority {
                Priority::P0Critical => self.accepted_p0.fetch_add(1, Ordering::Relaxed),
                Priority::P1Cluster  => self.accepted_p1.fetch_add(1, Ordering::Relaxed),
                Priority::P2Known    => self.accepted_p2.fetch_add(1, Ordering::Relaxed),
                Priority::P3New      => self.accepted_p3.fetch_add(1, Ordering::Relaxed),
            };
        } else {
            self.shed_total.fetch_add(1, Ordering::Relaxed);
        }

        accept
    }

    fn classify(&self, event: &ApiEvent) -> Priority {
        // P0: already suspended / critical score stored
        // (quick check via suspension map in engine — would need engine ref in prod)
        // Approximate: if account has cluster membership and large cluster → P0/P1
        if let Some(cid) = self.store.get_cluster(&event.account_id) {
            if self.store.cluster_members(cid).len() >= 5 {
                return Priority::P0Critical;
            }
            return Priority::P1Cluster;
        }

        if self.store.get_window(&event.account_id).is_some() {
            return Priority::P2Known;
        }

        Priority::P3New
    }

    pub fn stats(&self) -> ShedStats {
        ShedStats {
            shed_total:  self.shed_total.load(Ordering::Relaxed),
            accepted_p0: self.accepted_p0.load(Ordering::Relaxed),
            accepted_p1: self.accepted_p1.load(Ordering::Relaxed),
            accepted_p2: self.accepted_p2.load(Ordering::Relaxed),
            accepted_p3: self.accepted_p3.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShedStats {
    pub shed_total:  u64,
    pub accepted_p0: u64,
    pub accepted_p1: u64,
    pub accepted_p2: u64,
    pub accepted_p3: u64,
}

impl ShedStats {
    pub fn total_accepted(&self) -> u64 {
        self.accepted_p0 + self.accepted_p1 + self.accepted_p2 + self.accepted_p3
    }

    pub fn shed_rate(&self) -> f64 {
        let total = self.total_accepted() + self.shed_total;
        if total == 0 { 0.0 } else { self.shed_total as f64 / total as f64 }
    }
}
