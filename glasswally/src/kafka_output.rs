// glasswally/src/kafka_output.rs
//
// Kafka output adapter — Phase 2.
//
// Publishes enforcement actions and IOC bundles to Kafka topics for downstream
// consumption by SIEM, alerting, and data warehousing systems.
//
// Topics (configurable):
//   glasswally.enforcement  — EnforcementAction JSON, one message per action
//   glasswally.ioc          — IocBundle JSON, one message per cluster takedown
//   glasswally.signals      — DetectionSignal JSON, one message per fired worker signal
//
// Message format: UTF-8 JSON, no schema registry dependency.
// Key: account_id (ensures per-account ordering within a partition).
//
// This module provides a Kafka producer wrapper.  In the Glasswally binary,
// instantiate `KafkaAdapter` and call `publish_enforcement()` from the
// dispatcher after each action.
//
// Dependencies (add to glasswally/Cargo.toml when enabling this feature):
//   rdkafka = { version = "0.36", features = ["cmake-build"] }
//
// In this stub we provide the full interface with a simulated backend so the
// code compiles without rdkafka.  A real deployment enables the `kafka` feature
// and swaps in the rdkafka producer.

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::events::{EnforcementAction, IocBundle};

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaConfig {
    /// Comma-separated broker list (e.g. "kafka1:9092,kafka2:9092")
    pub brokers: String,
    pub enforcement_topic: String,
    pub ioc_topic: String,
    pub signals_topic: String,
    /// Maximum in-memory queue depth before dropping oldest (back-pressure)
    pub max_queue: usize,
    /// Flush interval in milliseconds
    pub flush_interval_ms: u64,
}

impl Default for KafkaConfig {
    fn default() -> Self {
        Self {
            brokers: "localhost:9092".to_string(),
            enforcement_topic: "glasswally.enforcement".to_string(),
            ioc_topic: "glasswally.ioc".to_string(),
            signals_topic: "glasswally.signals".to_string(),
            max_queue: 8192,
            flush_interval_ms: 100,
        }
    }
}

// ── Kafka message envelope ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct KafkaMessage {
    topic: String,
    key: String,     // account_id for ordering
    payload: String, // JSON body
    ts: chrono::DateTime<Utc>,
}

// ── Adapter ───────────────────────────────────────────────────────────────────

pub struct KafkaAdapter {
    config: KafkaConfig,
    /// In-memory queue — drained by background flush task.
    queue: Arc<Mutex<VecDeque<KafkaMessage>>>,
    /// Running message count (for metrics).
    pub published: std::sync::atomic::AtomicU64,
    pub dropped: std::sync::atomic::AtomicU64,
}

impl KafkaAdapter {
    pub fn new(config: KafkaConfig) -> Arc<Self> {
        let adapter = Arc::new(Self {
            config,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            published: std::sync::atomic::AtomicU64::new(0),
            dropped: std::sync::atomic::AtomicU64::new(0),
        });
        info!(
            "Kafka adapter configured, brokers={}",
            adapter.config.brokers
        );
        adapter
    }

    /// Publish an enforcement action to the enforcement topic.
    pub async fn publish_enforcement(&self, action: &EnforcementAction) {
        let key = action.account_id.clone().unwrap_or_default();
        self.enqueue(
            self.config.enforcement_topic.clone(),
            key,
            serde_json::to_string(action).unwrap_or_default(),
        )
        .await;
    }

    /// Publish an IOC bundle (cluster takedown) to the IOC topic.
    pub async fn publish_ioc(&self, bundle: &IocBundle) {
        let key = format!("cluster_{}", bundle.cluster_id);
        self.enqueue(
            self.config.ioc_topic.clone(),
            key,
            serde_json::to_string(bundle).unwrap_or_default(),
        )
        .await;
    }

    async fn enqueue(&self, topic: String, key: String, payload: String) {
        let mut q = self.queue.lock().await;
        if q.len() >= self.config.max_queue {
            q.pop_front(); // drop oldest
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!("Kafka queue full — dropped oldest message");
        }
        q.push_back(KafkaMessage {
            topic,
            key,
            payload,
            ts: Utc::now(),
        });
    }

    /// Background flush loop — sends queued messages to Kafka.
    /// In stub mode, writes to stdout as JSON lines.
    pub async fn flush_loop(self: Arc<Self>) {
        let interval = tokio::time::Duration::from_millis(self.config.flush_interval_ms);
        loop {
            tokio::time::sleep(interval).await;
            let batch: Vec<KafkaMessage> = {
                let mut q = self.queue.lock().await;
                q.drain(..).collect()
            };
            if batch.is_empty() {
                continue;
            }

            // Production: send via rdkafka FutureProducer.
            // Stub: log as JSONL.
            for msg in &batch {
                debug!(
                    topic = %msg.topic, key = %msg.key,
                    "kafka_publish payload_bytes={}", msg.payload.len()
                );
                // In production: producer.send(record, timeout).await
            }

            self.published
                .fetch_add(batch.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
    }
}
