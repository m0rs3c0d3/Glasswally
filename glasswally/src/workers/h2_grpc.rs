// glasswally/src/workers/h2_grpc.rs
//
// HTTP/2 SETTINGS frame + gRPC fingerprinting.
//
// Every HTTP/2 client library sends a SETTINGS frame at connection start.
// These frames contain tunable parameters that libraries ship with hardcoded
// defaults — independent of any fingerprinting evasion library.
//
// Known SETTINGS fingerprints:
//   python-httpx:   TABLE=4096  PUSH=0 WIN=65535       FRAME=16384
//   python-aiohttp: TABLE=4096  PUSH=0 WIN=65536        FRAME=16384
//   Go net/http2:   TABLE=4096  PUSH=0 WIN=1073741824  FRAME=16384
//   curl:           TABLE=4096  PUSH=1 WIN=65535        FRAME=16384
//   Chrome:         TABLE=65536 PUSH=1 WIN=6291456     FRAME=16384
//   Firefox:        TABLE=65536 PUSH=0 WIN=131072      FRAME=16384
//   Safari:         TABLE=4096  PUSH=0 WIN=4194304     FRAME=16384
//
// This layer is completely independent of Fingerprint Suite —
// that tool spoofs TLS ClientHello and HTTP/1.1 headers but does not
// intercept HTTP/2 SETTINGS frames.
//
// H2Settings are parsed by http_reconstruct.rs from the raw SSL capture.

use chrono::Utc;
use serde_json::json;

use crate::events::{ApiEvent, DetectionSignal, H2Settings, WorkerKind};
use crate::state::window::StateStore;

/// (label, header_table_size, enable_push, initial_window_size, max_frame_size)
const KNOWN_FINGERPRINTS: &[(&str, u32, u8, u32, u32)] = &[
    ("python_httpx", 4096, 0, 65535, 16384),
    ("python_aiohttp", 4096, 0, 65536, 16384),
    ("python_requests", 4096, 0, 65535, 16384), // requests uses httpx in v3
    ("go_net_http2", 4096, 0, 1073741824, 16384),
    ("curl", 4096, 1, 65535, 16384),
    ("node_undici", 4096, 0, 65535, 16384),
    ("okhttp", 4096, 0, 16777216, 16384),
    ("chrome", 65536, 1, 6291456, 16384),
    ("firefox", 65536, 0, 131072, 16384),
    ("safari", 4096, 0, 4194304, 16384),
    ("edge", 65536, 1, 6291456, 16384),
];

const BROWSER_LABELS: &[&str] = &["chrome", "firefox", "safari", "edge"];
const SCRIPT_LABELS: &[&str] = &[
    "python_httpx",
    "python_aiohttp",
    "python_requests",
    "go_net_http2",
    "curl",
    "node_undici",
    "okhttp",
];

fn identify(s: &H2Settings) -> Option<&'static str> {
    for (label, tbl, push, win, frame) in KNOWN_FINGERPRINTS {
        if s.header_table_size == *tbl
            && s.enable_push == *push
            && s.initial_window_size == *win
            && s.max_frame_size == *frame
        {
            return Some(label);
        }
    }
    None
}

pub async fn analyze(event: &ApiEvent, _store: &StateStore) -> Option<DetectionSignal> {
    let h2 = event.h2_settings.as_ref()?;

    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    let ua_lower = event.user_agent.to_lowercase();
    let ua_claims_browser = ["mozilla", "chrome", "firefox", "safari", "edge"]
        .iter()
        .any(|b| ua_lower.contains(b));

    let h2_label = identify(h2);

    if let Some(label) = h2_label {
        let h2_is_script = SCRIPT_LABELS.contains(&label);
        let h2_is_browser = BROWSER_LABELS.contains(&label);

        if ua_claims_browser && h2_is_script {
            // Smoking gun: browser UA + script SETTINGS — Fingerprint Suite blind spot
            score += 0.72;
            evidence.push(format!("h2_ua_mismatch:ua=browser,h2={}", label));
        } else if h2_is_script && !ua_claims_browser {
            score += 0.20;
            evidence.push(format!("h2_script_client:{}", label));
        } else if h2_is_browser && ua_claims_browser {
            // Consistent — mild positive signal only (could be legitimate)
            score += 0.02;
        }
    } else {
        // Unknown SETTINGS — custom-tuned client or novel library
        if ua_claims_browser {
            score += 0.15;
            evidence.push(format!(
                "h2_unknown_settings:fingerprint={}",
                h2.fingerprint
            ));
        }
    }

    // gRPC detection (HTTP/2 + grpc content-type or user-agent)
    let is_grpc = event
        .header_order
        .iter()
        .any(|h| h.to_lowercase().contains("grpc"))
        || ua_lower.contains("grpc");
    if is_grpc {
        score += 0.10;
        evidence.push("grpc_transport".into());
    }

    // Suspiciously large window size (tuned for bulk extraction throughput)
    if h2.initial_window_size > 200_000_000
        && h2_label
            .map(|l| SCRIPT_LABELS.contains(&l))
            .unwrap_or(false)
    {
        score += 0.15;
        evidence.push(format!("bulk_h2_window:{}", h2.initial_window_size));
    }

    if score == 0.0 {
        return None;
    }

    Some(DetectionSignal {
        worker: WorkerKind::H2Grpc,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence: 0.88,
        evidence,
        meta: [
            ("h2_fingerprint".into(), json!(h2.fingerprint)),
            ("h2_label".into(), json!(h2_label)),
            ("is_grpc".into(), json!(is_grpc)),
            ("ua_claims_browser".into(), json!(ua_claims_browser)),
        ]
        .into_iter()
        .collect(),
        timestamp: Utc::now(),
    })
}
