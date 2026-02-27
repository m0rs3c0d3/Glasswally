// glasswally/src/workers/watermark.rs
//
// Response watermarking — statistical attribution signatures.
//
// Embeds imperceptible zero-width Unicode markers in responses sent to
// flagged accounts. If those patterns appear in a public model release,
// distillation is confirmed and the campaign is attributed.
//
// Mechanism:
//   - 32-bit account-specific key: SHA256("gw_wm_v1:" || account_id)
//   - Encoded as ZWJ (bit=1) / ZWNJ (bit=0) inserted after spaces in text
//   - Invisible to readers, survives most copy-paste operations
//   - Detectable by scanning for ZWJ/ZWNJ sequences, comparing to registry
//
// This worker detects meta-attacks against the watermarking system:
//   - Prompts asking about invisible Unicode characters (probing)
//   - Zero-width characters arriving in inbound prompts (strip attempts)
//   - Accounts flagged for canary injection (returning watermarked content)

use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

const ZWJ: char = '\u{200D}'; // zero-width joiner   → bit 1
const ZWNJ: char = '\u{200C}'; // zero-width non-joiner → bit 0

/// Generate 32 deterministic watermark bits for an account.
/// Derived from SHA256("gw_wm_v1:" || account_id).
pub fn account_watermark_bits(account_id: &str) -> [bool; 32] {
    let mut h = Sha256::new();
    h.update(b"gw_wm_v1:");
    h.update(account_id.as_bytes());
    let d = h.finalize();
    let mut bits = [false; 32];
    for i in 0..32 {
        bits[i] = (d[i / 8] >> (i % 8)) & 1 == 1;
    }
    bits
}

/// Embed the account's watermark into a response string.
///
/// Inserts ZWJ (bit=1) or ZWNJ (bit=0) immediately after each space.
/// The 32-bit sequence cycles across the full text.
pub fn embed(text: &str, account_id: &str) -> String {
    let bits = account_watermark_bits(account_id);
    let mut out = String::with_capacity(text.len() + text.len() / 5);
    let mut bit_idx = 0usize;

    for ch in text.chars() {
        out.push(ch);
        if ch == ' ' {
            out.push(if bits[bit_idx % 32] { ZWJ } else { ZWNJ });
            bit_idx += 1;
        }
    }
    out
}

/// Scan text for a watermark matching any of the known accounts.
/// Returns (account_id, confidence 0..1) if ≥85% of bits match.
pub fn detect(text: &str, accounts: &[String]) -> Option<(String, f32)> {
    let extracted: Vec<bool> = text
        .chars()
        .filter(|&c| c == ZWJ || c == ZWNJ)
        .map(|c| c == ZWJ)
        .collect();

    if extracted.len() < 8 {
        return None;
    }

    for account_id in accounts {
        let expected = account_watermark_bits(account_id);
        let check_len = extracted.len().min(64);
        let matches = (0..check_len)
            .filter(|&i| extracted[i] == expected[i % 32])
            .count();
        let confidence = matches as f32 / check_len as f32;
        if confidence >= 0.85 {
            return Some((account_id.clone(), confidence));
        }
    }
    None
}

// ── Detection worker ──────────────────────────────────────────────────────────

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // ── Watermark probe detection ─────────────────────────────────────────────
    // Attacker testing whether our responses carry invisible markers.
    let probe_terms = [
        "zero-width",
        "invisible character",
        "hidden character",
        "unicode steganograph",
        "watermark detection",
        "\\u200",
        "u200c",
        "u200d",
        "u200b",
        "zwsp",
        "zero width",
        "strip whitespace",
        "normalize unicode",
        "remove formatting characters",
    ];
    let pl = event.prompt.to_lowercase();
    let probe_hits: Vec<&str> = probe_terms
        .iter()
        .filter(|&&t| pl.contains(t))
        .copied()
        .collect();
    if !probe_hits.is_empty() {
        score += 0.50;
        evidence.push(format!("wm_probe:{}", probe_hits.join(",")));
    }

    // ── ZWJ/ZWNJ in incoming prompt ───────────────────────────────────────────
    // Attacker reflecting watermarked text back, or testing strip routines.
    let zw_count = event
        .prompt
        .chars()
        .filter(|&c| c == ZWJ || c == ZWNJ || c == '\u{200B}')
        .count();
    if zw_count > 0 {
        score += 0.35;
        evidence.push(format!("zwsp_in_prompt:{}_markers", zw_count));
    }

    // ── Account already under active watermark surveillance ───────────────────
    if store.is_watermarked(&event.account_id) {
        score += 0.05;
        evidence.push("account_watermarked".into());
    }

    if score == 0.0 {
        return None;
    }

    Some(DetectionSignal {
        worker: WorkerKind::Watermark,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence: 0.80,
        evidence,
        meta: [
            ("zw_count".into(), json!(zw_count)),
            ("probe_hits".into(), json!(probe_hits.len())),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}
