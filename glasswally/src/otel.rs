// glasswally/src/otel.rs
//
// OpenTelemetry metrics exporter — Phase 5.
//
// Exposes Glasswally operational metrics in OpenTelemetry format, compatible
// with Prometheus scraping, OTLP export (Grafana, Datadog, Honeycomb, etc.),
// and any OTel-compatible observability backend.
//
// Metrics exposed:
//
//   glasswally_events_processed_total      Counter  — total events ingested
//   glasswally_alerts_total{tier}          Counter  — alerts by risk tier
//   glasswally_worker_score{worker}        Histogram — per-worker score distribution
//   glasswally_composite_score             Histogram — fused composite score distribution
//   glasswally_accounts_active             Gauge    — current active account windows
//   glasswally_clusters_active             Gauge    — current active clusters
//   glasswally_shed_total                  Counter  — events shed by load shedder
//   glasswally_kafka_published_total       Counter  — messages published to Kafka
//   glasswally_redis_checkpoint_latency_ms Histogram — checkpoint write latency
//   glasswally_ioc_bundles_published_total Counter  — IOC bundles published
//   glasswally_canaries_triggered_total    Counter  — canary tokens triggered
//
// Prometheus endpoint: GET /metrics (default port 9091)
//
// Dependencies (add to glasswally/Cargo.toml to enable):
//   opentelemetry      = { version = "0.23", features = ["metrics"] }
//   opentelemetry-prometheus = "0.16"
//   prometheus         = "0.13"

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::info;

use crate::events::{DetectionSignal, RiskTier};

// ── Metrics registry ──────────────────────────────────────────────────────────

pub struct GlasswallMetrics {
    pub events_processed: AtomicU64,
    pub alerts_critical: AtomicU64,
    pub alerts_high: AtomicU64,
    pub alerts_medium: AtomicU64,
    pub alerts_low: AtomicU64,
    pub shed_total: AtomicU64,
    pub kafka_published: AtomicU64,
    pub ioc_bundles: AtomicU64,
    pub canaries_triggered: AtomicU64,
    /// Per-worker score sums + counts for mean score export
    pub worker_score_sum: std::sync::Mutex<HashMap<String, (f64, u64)>>,
    /// Composite score buckets [0.0, 0.1), [0.1, 0.2), ... [0.9, 1.0)
    pub composite_buckets: [AtomicU64; 10],
}

impl GlasswallMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events_processed: AtomicU64::new(0),
            alerts_critical: AtomicU64::new(0),
            alerts_high: AtomicU64::new(0),
            alerts_medium: AtomicU64::new(0),
            alerts_low: AtomicU64::new(0),
            shed_total: AtomicU64::new(0),
            kafka_published: AtomicU64::new(0),
            ioc_bundles: AtomicU64::new(0),
            canaries_triggered: AtomicU64::new(0),
            worker_score_sum: std::sync::Mutex::new(HashMap::new()),
            composite_buckets: Default::default(),
        })
    }

    pub fn record_event(&self) {
        self.events_processed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_alert(&self, tier: RiskTier) {
        match tier {
            RiskTier::Critical => self.alerts_critical.fetch_add(1, Ordering::Relaxed),
            RiskTier::High => self.alerts_high.fetch_add(1, Ordering::Relaxed),
            RiskTier::Medium => self.alerts_medium.fetch_add(1, Ordering::Relaxed),
            RiskTier::Low => self.alerts_low.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub fn record_composite_score(&self, score: f32) {
        let bucket = ((score / 0.1) as usize).min(9);
        self.composite_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_worker_signal(&self, sig: &DetectionSignal) {
        if let Ok(mut map) = self.worker_score_sum.lock() {
            let entry = map.entry(sig.worker.to_string()).or_insert((0.0, 0));
            entry.0 += sig.score as f64;
            entry.1 += 1;
        }
    }

    /// Render metrics in Prometheus text exposition format.
    pub fn prometheus_text(&self, store_accounts: usize, store_clusters: usize) -> String {
        let mut out = String::with_capacity(4096);

        // Helper macros
        macro_rules! counter {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} counter\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }
        macro_rules! gauge {
            ($name:expr, $help:expr, $val:expr) => {
                out.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} gauge\n{} {}\n",
                    $name, $help, $name, $name, $val
                ));
            };
        }

        counter!(
            "glasswally_events_processed_total",
            "Total API events ingested",
            self.events_processed.load(Ordering::Relaxed)
        );

        out.push_str("# HELP glasswally_alerts_total Total alerts by risk tier\n");
        out.push_str("# TYPE glasswally_alerts_total counter\n");
        out.push_str(&format!(
            "glasswally_alerts_total{{tier=\"critical\"}} {}\n",
            self.alerts_critical.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "glasswally_alerts_total{{tier=\"high\"}} {}\n",
            self.alerts_high.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "glasswally_alerts_total{{tier=\"medium\"}} {}\n",
            self.alerts_medium.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "glasswally_alerts_total{{tier=\"low\"}} {}\n",
            self.alerts_low.load(Ordering::Relaxed)
        ));

        gauge!(
            "glasswally_accounts_active",
            "Current active account windows in StateStore",
            store_accounts
        );
        gauge!(
            "glasswally_clusters_active",
            "Current active clusters in StateStore",
            store_clusters
        );

        counter!(
            "glasswally_shed_total",
            "Events dropped by load shedder",
            self.shed_total.load(Ordering::Relaxed)
        );
        counter!(
            "glasswally_kafka_published_total",
            "Messages published to Kafka",
            self.kafka_published.load(Ordering::Relaxed)
        );
        counter!(
            "glasswally_ioc_bundles_published_total",
            "IOC bundles published to feed",
            self.ioc_bundles.load(Ordering::Relaxed)
        );
        counter!(
            "glasswally_canaries_triggered_total",
            "Canary tokens triggered (distillation confirmed)",
            self.canaries_triggered.load(Ordering::Relaxed)
        );

        // Per-worker mean score
        out.push_str("# HELP glasswally_worker_mean_score Mean detection score per worker\n");
        out.push_str("# TYPE glasswally_worker_mean_score gauge\n");
        if let Ok(map) = self.worker_score_sum.lock() {
            for (worker, (sum, count)) in map.iter() {
                let mean = if *count > 0 { sum / *count as f64 } else { 0.0 };
                out.push_str(&format!(
                    "glasswally_worker_mean_score{{worker=\"{}\"}} {:.4}\n",
                    worker, mean
                ));
            }
        }

        // Composite score histogram
        out.push_str("# HELP glasswally_composite_score_bucket Composite score distribution (0.1-wide buckets)\n");
        out.push_str("# TYPE glasswally_composite_score_bucket counter\n");
        for (i, bucket) in self.composite_buckets.iter().enumerate() {
            out.push_str(&format!(
                "glasswally_composite_score_bucket{{le=\"{:.1}\"}} {}\n",
                (i + 1) as f64 * 0.1,
                bucket.load(Ordering::Relaxed)
            ));
        }

        out
    }
}

// ── HTTP /metrics endpoint ─────────────────────────────────────────────────────

pub struct MetricsServer {
    pub metrics: Arc<GlasswallMetrics>,
    addr: SocketAddr,
}

impl MetricsServer {
    pub fn new(metrics: Arc<GlasswallMetrics>, addr: SocketAddr) -> Self {
        Self { metrics, addr }
    }

    pub async fn serve(
        self: Arc<Self>,
        store: Arc<crate::state::window::StateStore>,
    ) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("OTel /metrics endpoint listening on {}", self.addr);

        loop {
            let (mut stream, _) = listener.accept().await?;
            let metrics = Arc::clone(&self.metrics);
            let store = Arc::clone(&store);

            tokio::spawn(async move {
                let body = metrics.prometheus_text(store.n_accounts(), store.n_clusters());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    }
}
