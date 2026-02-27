// glasswally/src/ioc_feed.rs
//
// Cross-provider IOC sharing protocol.
//
// Format: signed NDJSON — one IocFeedEntry per line.
// Signing: HMAC-SHA256(canonical_bundle_json, shared_key).
//
// Protocol design goals:
//   - Zero additional infrastructure (no TAXII server, no Kafka)
//   - Single-file NDJSON feed consumable by any provider
//   - Tamper-evident: entries with invalid signatures are silently dropped
//   - Fresh-only: entries with last_seen > 24h are skipped on ingest
//
// Workflow:
//   Provider A detects cluster → writes ioc_feed.ndjson
//   Provider B fetches that feed → IocFeedConsumer::consume()
//   Consumer pre-scores all accounts/IPs/JA3s in the bundle
//   Cluster graph at B immediately incorporates the IOCs
//
// This means detecting a campaign at Anthropic auto-raises risk scores
// at OpenAI/Google/Mistral for the same IPs/JA3s — before the campaign
// switches target providers.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::events::IocBundle;

type HmacSha256 = Hmac<sha2::Sha256>;

// ── Feed entry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocFeedEntry {
    pub schema_version: String,   // "glasswally/ioc/v1"
    pub provider_id:    String,   // e.g. "anthropic", "openai", "mistral"
    pub bundle:         IocBundle,
    pub signature:      String,   // hex(HMAC-SHA256(canonical_json, key))
    pub exported_at:    DateTime<Utc>,
}

impl IocFeedEntry {
    pub fn new(bundle: IocBundle, provider_id: impl Into<String>, signing_key: &[u8]) -> Self {
        let provider_id = provider_id.into();
        let canonical   = serde_json::to_string(&bundle).unwrap_or_default();
        let signature   = hmac_sign(canonical.as_bytes(), signing_key);
        Self {
            schema_version: "glasswally/ioc/v1".into(),
            provider_id,
            bundle,
            signature,
            exported_at: Utc::now(),
        }
    }

    /// Verify the HMAC signature. Constant-time comparison.
    pub fn verify(&self, key: &[u8]) -> bool {
        let canonical = serde_json::to_string(&self.bundle).unwrap_or_default();
        let expected  = hmac_sign(canonical.as_bytes(), key);
        // Constant-time XOR comparison
        let a = expected.as_bytes();
        let b = self.signature.as_bytes();
        if a.len() != b.len() { return false; }
        a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    /// True if this IOC was active in the last 24 hours.
    pub fn is_fresh(&self) -> bool {
        Utc::now() - self.bundle.last_seen < Duration::hours(24)
    }

    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default() + "\n"
    }
}

// ── Feed generator ────────────────────────────────────────────────────────────

pub struct IocFeedGenerator {
    provider_id: String,
    signing_key: Vec<u8>,
    entries:     Vec<IocFeedEntry>,
}

impl IocFeedGenerator {
    pub fn new(provider_id: impl Into<String>, signing_key: Vec<u8>) -> Self {
        Self { provider_id: provider_id.into(), signing_key, entries: Vec::new() }
    }

    /// Add a bundle. Only bundles with confidence ≥ 0.70 are exported.
    pub fn add(&mut self, bundle: IocBundle) {
        if bundle.confidence < 0.70 { return; }
        let entry = IocFeedEntry::new(bundle, &self.provider_id, &self.signing_key);
        self.entries.push(entry);
    }

    /// Serialize all entries as an NDJSON string.
    pub fn export_ndjson(&self) -> String {
        self.entries.iter().map(|e| e.to_jsonl()).collect()
    }

    /// Append all entries to a file.
    pub async fn export_to_file(&self, path: &Path) -> Result<()> {
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        let ndjson = self.export_ndjson();
        if ndjson.is_empty() { return Ok(()); }
        let mut f = OpenOptions::new().create(true).append(true).open(path).await?;
        f.write_all(ndjson.as_bytes()).await?;
        Ok(())
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

// ── Feed consumer ─────────────────────────────────────────────────────────────

pub struct IocFeedConsumer {
    verification_key: Vec<u8>,
    min_confidence:   f32,
}

impl IocFeedConsumer {
    pub fn new(verification_key: Vec<u8>) -> Self {
        Self { verification_key, min_confidence: 0.70 }
    }

    pub fn with_min_confidence(mut self, threshold: f32) -> Self {
        self.min_confidence = threshold;
        self
    }

    /// Parse and verify an NDJSON feed string. Returns only valid, fresh entries.
    pub fn consume(&self, ndjson: &str) -> Vec<IocFeedEntry> {
        ndjson.lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() { return None; }
                serde_json::from_str::<IocFeedEntry>(line).ok()
            })
            .filter(|e| {
                e.verify(&self.verification_key)
                    && e.is_fresh()
                    && e.bundle.confidence >= self.min_confidence
            })
            .collect()
    }

    /// Read and consume from a file.
    pub async fn consume_file(&self, path: &Path) -> Result<Vec<IocFeedEntry>> {
        let content = tokio::fs::read_to_string(path).await?;
        Ok(self.consume(&content))
    }
}

// ── HMAC helper ───────────────────────────────────────────────────────────────

fn hmac_sign(data: &[u8], key: &[u8]) -> String {
    // Fallback to a fixed key if the provided key is empty (dev-only)
    let effective_key = if key.is_empty() { b"glasswally_dev_key".as_ref() } else { key };
    let mut mac = HmacSha256::new_from_slice(effective_key)
        .expect("HMAC key length error");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}
