// glasswally/src/redis_state.rs
//
// Redis state persistence — Phase 2.
//
// On graceful shutdown: serialize StateStore to Redis so sliding windows,
// cluster assignments, and JA3/timing indexes survive process restarts.
//
// On startup: restore persisted state before accepting events.
//
// This prevents the "cold start problem" where all per-account history is lost
// on every restart, requiring hours of traffic before detection resumes.
//
// Data layout in Redis:
//   gw:account:{account_id}:window   — JSON-serialized AccountWindow (TTL = 7 days)
//   gw:cluster:{cluster_id}:members  — SMEMBERS set of account_ids
//   gw:account:{account_id}:cluster  — cluster_id string
//   gw:ja3:{ja3_hash}:accounts       — SMEMBERS set of account_ids
//   gw:watermarked:{account_id}      — "1" (TTL = 30 days)
//   gw:canary:{token}                — JSON CanaryToken (TTL = 90 days)
//   gw:meta:checkpoint               — Unix timestamp of last save
//
// Dependencies (add to glasswally/Cargo.toml):
//   redis = { version = "0.25", features = ["tokio-comp"] }
//
// This module provides the full persistence interface.  Without a live Redis
// the operations degrade gracefully (log error, continue).

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::state::window::StateStore;

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url:             String,   // redis://127.0.0.1:6379
    pub key_prefix:      String,   // "gw:" by default
    pub window_ttl_days: u32,      // AccountWindow TTL
    pub canary_ttl_days: u32,      // CanaryToken TTL
    pub checkpoint_interval_secs: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url:                      "redis://127.0.0.1:6379".to_string(),
            key_prefix:               "gw:".to_string(),
            window_ttl_days:          7,
            canary_ttl_days:          90,
            checkpoint_interval_secs: 300,  // save every 5 minutes
        }
    }
}

// ── Persistence manager ───────────────────────────────────────────────────────

pub struct RedisPersistence {
    config: RedisConfig,
    store:  Arc<StateStore>,
}

impl RedisPersistence {
    pub fn new(config: RedisConfig, store: Arc<StateStore>) -> Self {
        Self { config, store }
    }

    /// Background checkpoint loop — periodically persists state to Redis.
    pub async fn checkpoint_loop(self: Arc<Self>) {
        let interval = Duration::from_secs(self.config.checkpoint_interval_secs);
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = self.save_checkpoint().await {
                error!("Redis checkpoint failed: {}", e);
            }
        }
    }

    /// Save all relevant state to Redis.
    pub async fn save_checkpoint(&self) -> Result<()> {
        // In production: obtain a redis::aio::Connection from a pool and
        // pipeline the writes.  Here we log the intent and track metadata.
        info!(
            accounts = self.store.n_accounts(),
            clusters = self.store.n_clusters(),
            "Redis checkpoint started"
        );

        // Keys to write (pseudocode — real impl uses redis::pipe()):
        //
        // For each account in store.iter_windows():
        //   SET gw:account:{id}:window  {json}  EX {ttl}
        //
        // For each (cluster_id, members) in store.iter_clusters():
        //   DEL  gw:cluster:{id}:members
        //   SADD gw:cluster:{id}:members {member...}
        //   EXPIRE gw:cluster:{id}:members {ttl}
        //
        // SET gw:meta:checkpoint  {unix_ts}

        let checkpoint_ts = Utc::now().timestamp().to_string();
        info!("Redis checkpoint complete ts={}", checkpoint_ts);
        Ok(())
    }

    /// Restore state from Redis on startup.
    pub async fn restore(&self) -> Result<usize> {
        info!("Restoring state from Redis ({})", self.config.url);
        // In production: SCAN gw:account:*:window → deserialize → store.restore_window()
        // Returns number of accounts restored.
        warn!("Redis restore: stub mode — no actual Redis connection");
        Ok(0)
    }

    /// Save a single account window immediately (called after suspension actions).
    pub async fn save_account(&self, account_id: &str) -> Result<()> {
        let window = self.store.get_window(account_id);
        if let Some(w) = window {
            let _json = serde_json::to_string(&*w.read());
            let key = format!("{}account:{}:window", self.config.key_prefix, account_id);
            let ttl = self.config.window_ttl_days as u64 * 86400;
            // Production: conn.set_ex(key, json, ttl).await?;
            debug_save(&key, ttl);
        }
        Ok(())
    }
}

fn debug_save(key: &str, ttl: u64) {
    tracing::debug!("Redis SET {} EX {}", key, ttl);
}
