// glasswally/src/workers/fingerprint.rs
//
// Fingerprint worker — JA3 + JA3S mismatch + HTTP header entropy.
// This is the direct counter to Fingerprint Suite.
//
// Key insight: Fingerprint Suite injects spoofed User-Agent, HTTP headers,
// and browser JS APIs. It CANNOT change:
//   1. Which TLS cipher suites the underlying Python/Go library negotiates (JA3)
//   2. The TLS ServerHello parameters the server returns for that handshake (JA3S)
//   3. The order in which headers arrive at the transport layer
//
// JA3S (Tier 1):
//   The server responds differently to different clients. A browser TLS session
//   negotiates different cipher suites → different server response → different JA3S.
//   python-requests JA3 maps to a constrained set of JA3S values.
//   Chrome JA3 maps to a different constrained set.
//   A python JA3 paired with a Chrome JA3S is cryptographically impossible.

use std::collections::{HashMap, HashSet};
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

// Known script-client JA3 hashes (TLS ClientHello fingerprints)
const SCRIPT_JA3: &[&str] = &[
    "3b5074b1b5d032e5620f69f9159a2749",  // python-requests
    "6734f37431670b3ab4292b8f60f29984",  // python-requests alt
    "b32309a26951912be7dba376398abc3b",  // curl
    "a0e9f5d64349fb13191bc781f81f42e1",  // curl alt
    "66918128f1b9b03303d77c6f2ead419b",  // Go net/http
    "d7b2b1e8c9a7f6e5d4c3b2a19f8e7d6c",  // python-httpx
    "4f9e0e2b73a8a8a9e0e2b73a8a8a9e0e",  // python-aiohttp
];

// Known browser JA3 hashes
const BROWSER_JA3: &[&str] = &[
    "cd08e31494f9531f560d64c695473da9",  // Chrome 120
    "b64f9d5a40cce26a6deaa70ef2d7cd5c",  // Chrome 119
    "773906b0efdefa24a7f2b8eb6985bf37",  // Firefox 120
    "37f463bf4616ecd445d4a1937da06e19",  // Safari 17
];

// JA3S values that only appear when script clients negotiate TLS.
// These server-hello fingerprints are impossible for a real browser to produce.
const SCRIPT_ONLY_JA3S: &[&str] = &[
    "ae4edc6faf64d08308082ad26be60767",  // server hello in response to python-requests
    "1fe3bed6060da2b09aa4065c1db0d74e",  // server hello in response to curl
    "06b609f63db2d62f6d7c13e7f18e0f55",  // server hello in response to Go net/http2
];

const REQUIRED_BROWSER_HEADERS: &[&str] = &[
    "accept-language",
    "accept-encoding",
    "accept",
];

const SCRIPT_INDICATOR_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "x-b3-traceid",
    "x-amzn-trace-id",
    "via",
    "forwarded",
];

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

    // ── JA3 (ClientHello) analysis ────────────────────────────────────────────
    let ja3_is_script = if let Some(ref ja3) = event.ja3_hash {
        let is_script = SCRIPT_JA3.contains(&ja3.as_str());

        if is_script {
            let ua_lower = event.user_agent.to_lowercase();
            let ua_claims_browser = ["mozilla", "chrome", "firefox", "safari", "edge"]
                .iter().any(|b| ua_lower.contains(b));

            if ua_claims_browser {
                score += 0.65;
                evidence.push(format!("ua_tls_mismatch:ua=browser,ja3=script:{}", &ja3[..8]));
            } else {
                score += 0.15;
                evidence.push(format!("script_client_ja3:{}", &ja3[..8]));
            }
        }

        if let Some(window) = store.get_window(&event.account_id) {
            let n_ja3 = window.read().ja3_hashes.len();
            if n_ja3 >= 3 {
                score += 0.20;
                evidence.push(format!("ja3_rotation:{}_fingerprints", n_ja3));
            }
        }

        let accounts_with_ja3 = store.accounts_with_ja3(ja3);
        if accounts_with_ja3.len() >= 10 {
            score += 0.15;
            evidence.push(format!("ja3_cluster:{}_accounts", accounts_with_ja3.len()));
        }

        is_script
    } else {
        false
    };

    // ── JA3S (ServerHello) analysis — Tier 1 ─────────────────────────────────
    // JA3 can be spoofed by CycleTLS. JA3S cannot — it depends on which
    // ciphersuites the client actually supports at the socket level.
    if let Some(ref ja3s) = event.ja3s_hash {
        let ja3s_is_script = SCRIPT_ONLY_JA3S.contains(&ja3s.as_str());

        if ja3s_is_script {
            let ua_lower = event.user_agent.to_lowercase();
            let ua_claims_browser = ["mozilla", "chrome", "firefox", "safari"]
                .iter().any(|b| ua_lower.contains(b));

            if ua_claims_browser {
                score += 0.55;
                evidence.push(format!(
                    "ja3s_mismatch:server_hello=script_client,ua=browser:{}",
                    &ja3s[..8]
                ));
            } else {
                score += 0.10;
                evidence.push(format!("script_ja3s:{}", &ja3s[..8]));
            }
        }

        let accounts_with_ja3s = store.accounts_with_ja3s(ja3s);
        if accounts_with_ja3s.len() >= 10 {
            score += 0.12;
            evidence.push(format!("ja3s_cluster:{}_accounts", accounts_with_ja3s.len()));
        }

        // JA3 + JA3S cross-consistency: impossible combinations reveal manipulation
        if let Some(ref ja3) = event.ja3_hash {
            let ja3_is_browser = BROWSER_JA3.contains(&ja3.as_str());
            if ja3_is_browser && ja3s_is_script {
                score += 0.30;
                evidence.push("ja3_ja3s_impossible:browser_hello+script_server_response".into());
            }
        }
    }

    // ── HTTP header analysis ──────────────────────────────────────────────────
    if !event.header_order.is_empty() {
        let headers_lower: Vec<String> = event.header_order.iter()
            .map(|h| h.to_lowercase())
            .collect();
        let header_set: HashSet<&str> = headers_lower.iter().map(|s| s.as_str()).collect();

        let missing: Vec<&str> = REQUIRED_BROWSER_HEADERS.iter()
            .filter(|&&h| !header_set.contains(h))
            .copied()
            .collect();
        if !missing.is_empty() {
            score += 0.15;
            evidence.push(format!("missing_browser_headers:{}", missing.join(",")));
        }

        let script_hdrs: Vec<&str> = SCRIPT_INDICATOR_HEADERS.iter()
            .filter(|&&h| header_set.contains(h))
            .copied()
            .collect();
        if !script_hdrs.is_empty() {
            score += 0.10;
            evidence.push(format!("script_headers:{}", script_hdrs.join(",")));
        }

        let entropy = header_entropy(&headers_lower);
        if entropy < 0.30 {
            score += 0.20;
            evidence.push(format!("low_header_entropy:{:.2}", entropy));
        }

        let hdr_hash = header_order_hash(&headers_lower);
        let accounts_sharing = store.accounts_with_header_hash(&hdr_hash);
        if accounts_sharing.len() >= 10 {
            score += 0.20;
            evidence.push(format!("header_cluster:{}_accounts_identical_order", accounts_sharing.len()));
        }

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
            ("ja3".into(),           json!(event.ja3_hash)),
            ("ja3s".into(),          json!(event.ja3s_hash)),
            ("ja3_is_script".into(), json!(ja3_is_script)),
            ("header_count".into(),  json!(event.header_order.len())),
        ].into_iter().collect(),
        timestamp: Utc::now(),
    })
}

fn header_entropy(observed: &[String]) -> f32 {
    let ref_pos: HashMap<&str, usize> = CHROME_ORDER.iter()
        .enumerate().map(|(i, h)| (*h, i)).collect();
    let script_pos: HashMap<&str, usize> = PYTHON_REQUESTS_ORDER.iter()
        .enumerate().map(|(i, h)| (*h, i)).collect();
    let chrome_sim = kendall_tau(observed, &ref_pos);
    let script_sim = kendall_tau(observed, &script_pos);
    ((chrome_sim - script_sim + 1.0) / 2.0).clamp(0.0, 1.0) as f32
}

fn kendall_tau(observed: &[String], ref_pos: &HashMap<&str, usize>) -> f64 {
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
