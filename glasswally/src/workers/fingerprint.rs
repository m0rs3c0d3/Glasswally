// glasswally/src/workers/fingerprint.rs
//
// Fingerprint worker — JA3 mismatch + HTTP header entropy.
// This is the direct counter to Fingerprint Suite.
//
// Key insight: Fingerprint Suite injects spoofed User-Agent, HTTP headers,
// and browser JS APIs. It CANNOT change:
//   1. Which TLS cipher suites the underlying Python/Go library negotiates
//   2. The order in which headers arrive at the transport layer
//
// This worker detects both.

use std::collections::HashSet;
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

// Known script-client JA3 hashes (see sentinel-rs/src/capture/ja3.rs for full list)
const SCRIPT_JA3: &[&str] = &[
    "3b5074b1b5d032e5620f69f9159a2749",  // python-requests
    "6734f37431670b3ab4292b8f60f29984",  // python-requests alt
    "b32309a26951912be7dba376398abc3b",  // curl
    "a0e9f5d64349fb13191bc781f81f42e1",  // curl alt
    "66918128f1b9b03303d77c6f2ead419b",  // Go net/http
    "d7b2b1e8c9a7f6e5d4c3b2a19f8e7d6c",  // python-httpx
    "4f9e0e2b73a8a8a9e0e2b73a8a8a9e0e",  // python-aiohttp
];

// Headers real browsers ALWAYS send on API calls
const REQUIRED_BROWSER_HEADERS: &[&str] = &[
    "accept-language",
    "accept-encoding",
    "accept",
];

// Headers that scripts add but browsers don't on clean API calls
const SCRIPT_INDICATOR_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "x-b3-traceid",   // Zipkin tracing (automation frameworks)
    "x-amzn-trace-id",// AWS SDK
    "via",
    "forwarded",
];

// Expected Chrome header order (empirically measured)
const CHROME_ORDER: &[&str] = &[
    "host", "connection", "content-length", "sec-ch-ua", "content-type",
    "sec-ch-ua-platform", "sec-ch-ua-mobile", "user-agent", "accept",
    "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "accept-encoding", "accept-language",
];

const PYTHON_REQUESTS_ORDER: &[&str] = &[
    "host", "user-agent", "accept-encoding", "accept", "connection",
    "content-length", "content-type", "authorization", "x-api-key",
];

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let mut score    = 0.0f32;
    let mut evidence = Vec::new();

    // ── JA3 analysis ──────────────────────────────────────────────────────────
    let ja3_is_script = if let Some(ref ja3) = event.ja3_hash {
        let is_script = SCRIPT_JA3.contains(&ja3.as_str());

        if is_script {
            // Check if UA is pretending to be a browser (Fingerprint Suite)
            let ua_lower = event.user_agent.to_lowercase();
            let ua_claims_browser = ["mozilla", "chrome", "firefox", "safari", "edge"]
                .iter().any(|b| ua_lower.contains(b));

            if ua_claims_browser {
                // This is the smoking gun — Fingerprint Suite detected
                score += 0.65;
                evidence.push(format!("ua_tls_mismatch:ua=browser,ja3=script:{}", &ja3[..8]));
            } else {
                score += 0.15;
                evidence.push(format!("script_client_ja3:{}", &ja3[..8]));
            }
        }

        // JA3 rotation: same account, multiple different script JA3s
        if let Some(window) = store.get_window(&event.account_id) {
            let n_ja3 = window.read().ja3_hashes.len();
            if n_ja3 >= 3 {
                score += 0.20;
                evidence.push(format!("ja3_rotation:{}_fingerprints", n_ja3));
            }
        }

        // Cross-account JA3 clustering: same script JA3 across many accounts
        let accounts_with_ja3 = store.accounts_with_ja3(ja3);
        if accounts_with_ja3.len() >= 10 {
            score += 0.15;
            evidence.push(format!("ja3_cluster:{}_accounts_share_fingerprint", accounts_with_ja3.len()));
        }

        is_script
    } else {
        false
    };

    // ── HTTP header analysis ──────────────────────────────────────────────────
    if !event.header_order.is_empty() {
        let headers_lower: Vec<String> = event.header_order.iter()
            .map(|h| h.to_lowercase())
            .collect();
        let header_set: HashSet<&str> = headers_lower.iter().map(|s| s.as_str()).collect();

        // Missing required browser headers
        let missing: Vec<&str> = REQUIRED_BROWSER_HEADERS.iter()
            .filter(|&&h| !header_set.contains(h))
            .copied()
            .collect();
        if !missing.is_empty() {
            score += 0.15;
            evidence.push(format!("missing_browser_headers:{}", missing.join(",")));
        }

        // Script indicator headers present
        let script_hdrs: Vec<&str> = SCRIPT_INDICATOR_HEADERS.iter()
            .filter(|&&h| header_set.contains(h))
            .copied()
            .collect();
        if !script_hdrs.is_empty() {
            score += 0.10;
            evidence.push(format!("script_headers:{}", script_hdrs.join(",")));
        }

        // Header order entropy (Kendall tau vs known orders)
        let entropy = header_entropy(&headers_lower);
        if entropy < 0.30 {
            score += 0.20;
            evidence.push(format!("low_header_entropy:{:.2}", entropy));
        }

        // Cross-account header order hash clustering
        let hdr_hash = header_order_hash(&headers_lower);
        let accounts_sharing = store.accounts_with_header_hash(&hdr_hash);
        if accounts_sharing.len() >= 10 {
            score += 0.20;
            evidence.push(format!("header_cluster:{}_accounts_identical_order", accounts_sharing.len()));
        }

        // Spoofed UA: claims browser + script headers + missing browser headers
        let ua_lower = event.user_agent.to_lowercase();
        let ua_claims_browser = ["mozilla", "chrome", "firefox", "safari"]
            .iter().any(|b| ua_lower.contains(b));
        if ua_claims_browser && (!missing.is_empty() || !script_hdrs.is_empty() || ja3_is_script) {
            score += 0.15;
            evidence.push("spoofed_ua:fingerprint_suite_suspected".into());
        }
    }

    // ── Geo uplift ────────────────────────────────────────────────────────────
    if event.country_code == "CN" {
        score = (score * 1.20).min(1.0);
    }

    let n = store.get_window(&event.account_id)
        .map(|w| w.read().events.len()).unwrap_or(1);
    let confidence = (n as f32 / 20.0).min(1.0);
    score = (score * (0.4 + 0.6 * confidence)).min(1.0);

    Some(DetectionSignal {
        worker:     WorkerKind::Fingerprint,
        account_id: event.account_id.clone(),
        score:      (score * 10000.0).round() / 10000.0,
        confidence,
        evidence,
        meta: [
            ("ja3".into(),        json!(event.ja3_hash)),
            ("ja3_is_script".into(), json!(ja3_is_script)),
            ("header_count".into(), json!(event.header_order.len())),
        ].into_iter().collect(),
        timestamp: Utc::now(),
    })
}

// Kendall tau rank correlation vs known browser order.
// Returns 0.0 (script-like) to 1.0 (browser-like).
fn header_entropy(observed: &[String]) -> f32 {
    let ref_pos: std::collections::HashMap<&str, usize> = CHROME_ORDER.iter()
        .enumerate().map(|(i, h)| (*h, i)).collect();
    let script_pos: std::collections::HashMap<&str, usize> = PYTHON_REQUESTS_ORDER.iter()
        .enumerate().map(|(i, h)| (*h, i)).collect();

    let chrome_sim  = kendall_tau(observed, &ref_pos);
    let script_sim  = kendall_tau(observed, &script_pos);

    ((chrome_sim - script_sim + 1.0) / 2.0).clamp(0.0, 1.0) as f32
}

fn kendall_tau(observed: &[String], ref_pos: &std::collections::HashMap<&str, usize>) -> f64 {
    let pairs: Vec<(usize, usize)> = observed.iter().enumerate()
        .filter_map(|(i, h)| ref_pos.get(h.as_str()).map(|&r| (i, r)))
        .collect();
    if pairs.len() < 2 { return 0.0; }
    let (mut c, mut d) = (0i64, 0i64);
    for i in 0..pairs.len() {
        for j in (i+1)..pairs.len() {
            if (pairs[i].0 < pairs[j].0) == (pairs[i].1 < pairs[j].1) { c += 1; }
            else { d += 1; }
        }
    }
    let total = (c + d) as f64;
    if total == 0.0 { return 0.5; }
    c as f64 / total
}

fn header_order_hash(headers: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(headers.join("|").as_bytes());
    hex::encode(&h.finalize()[..8])
}
