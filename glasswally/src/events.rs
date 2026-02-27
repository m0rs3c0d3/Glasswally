// glasswally/src/events.rs
//
// Shared event types and all domain types flowing through Glasswally.
// These mirror the BPF structs in glasswally-ebpf/src/main.rs
// and must be kept in sync (same repr(C) layout).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

pub const MAX_BUF: usize = 4096;

// ── Raw events from BPF ───────────────────────────────────────────────────────

/// Raw SSL event from kernel — plaintext captured at ssl_write/ssl_read.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct RawSslEvent {
    pub pid:       u32,
    pub tid:       u32,
    pub fd:        i32,
    pub direction: u8,       // 0=write, 1=read
    pub buf_len:   u32,
    pub buf:       [u8; MAX_BUF],
}

/// Direction of SSL data capture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslDirection {
    Write,  // outbound — API request (prompt)
    Read,   // inbound  — API response
}

impl From<u8> for SslDirection {
    fn from(v: u8) -> Self {
        match v { 1 => Self::Read, _ => Self::Write }
    }
}

/// Raw TCP connection event from kernel.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct RawConnEvent {
    pub pid:      u32,
    pub fd:       i32,
    pub src_ip:   u32,    // network byte order
    pub dst_ip:   u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub kind:     u8,     // 0=connect, 1=close
}

// ── Parsed / enriched events ──────────────────────────────────────────────────

/// Parsed SSL event — text extracted, pid correlated to account.
#[derive(Debug, Clone)]
pub struct SslCapture {
    pub pid:        u32,
    pub fd:         i32,
    pub direction:  SslDirection,
    pub text:       String,          // UTF-8 decoded (lossy)
    pub timestamp:  DateTime<Utc>,
    pub account_id: Option<String>,  // correlated from pid→account map
    pub conn_key:   Option<ConnKey>,
}

/// TCP connection 5-tuple — used to correlate SSL events with accounts.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnKey {
    pub src_ip:   IpAddr,
    pub src_port: u16,
    pub dst_ip:   IpAddr,
    pub dst_port: u16,
}

impl std::fmt::Display for ConnKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} → {}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
}

/// HTTP request reconstructed from SSL captures.
/// Multiple SSL events may be needed to reconstruct one HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub conn_key:    Option<ConnKey>,
    pub method:      String,
    pub path:        String,
    pub headers:     Vec<(String, String)>,  // in arrival order (for header fingerprint)
    pub body:        String,
    pub timestamp:   DateTime<Utc>,
    pub account_id:  Option<String>,
    pub model:       Option<String>,         // extracted from path or body
    pub prompt:      Option<String>,         // extracted from JSON body
    pub token_count: Option<u32>,
}

impl HttpRequest {
    /// Extract headers in arrival order (for header entropy analysis).
    pub fn header_names_in_order(&self) -> Vec<String> {
        self.headers.iter().map(|(k, _)| k.to_lowercase()).collect()
    }

    /// Find a specific header value (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers.iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

// ── Parsed API event (same as sentinel ApiEvent, from HTTP request) ───────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvent {
    pub request_id:          String,
    pub account_id:          String,
    pub timestamp:           DateTime<Utc>,
    pub ip_address:          IpAddr,
    pub user_agent:          String,
    pub model:               String,
    pub prompt:              String,
    pub token_count:         u32,
    pub payment_method_hash: Option<String>,
    pub org_id:              Option<String>,
    pub country_code:        String,
    pub header_order:        Vec<String>,   // NEW — from eBPF HTTP reconstruction
    pub ja3_hash:            Option<String>,// NEW — from TLS ClientHello
    pub campaign_label:      Option<String>,
}

// ── Detection types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WorkerKind {
    Fingerprint,
    Velocity,
    Cot,
    Semantic,
    Hydra,
    Pivot,
}

impl std::fmt::Display for WorkerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fingerprint => write!(f, "fingerprint"),
            Self::Velocity    => write!(f, "velocity"),
            Self::Cot         => write!(f, "cot"),
            Self::Semantic    => write!(f, "semantic"),
            Self::Hydra       => write!(f, "hydra"),
            Self::Pivot       => write!(f, "pivot"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub worker:     WorkerKind,
    pub account_id: String,
    pub score:      f32,
    pub confidence: f32,
    pub evidence:   Vec<String>,
    pub meta:       HashMap<String, serde_json::Value>,
    pub timestamp:  DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier { Low, Medium, High, Critical }

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low      => write!(f, "LOW"),
            Self::Medium   => write!(f, "MEDIUM"),
            Self::High     => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionKind {
    Monitor, RateLimit, FlagForReview, SuspendAccount, ClusterTakedown, IntelShare,
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor         => write!(f, "MONITOR"),
            Self::RateLimit       => write!(f, "RATE_LIMIT"),
            Self::FlagForReview   => write!(f, "FLAG_FOR_REVIEW"),
            Self::SuspendAccount  => write!(f, "SUSPEND_ACCOUNT"),
            Self::ClusterTakedown => write!(f, "CLUSTER_TAKEDOWN"),
            Self::IntelShare      => write!(f, "INTEL_SHARE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDecision {
    pub account_id:      String,
    pub composite_score: f32,
    pub tier:            RiskTier,
    pub signal_scores:   HashMap<String, f32>,
    pub top_evidence:    Vec<String>,
    pub country_codes:   Vec<String>,
    pub cluster_id:      Option<u32>,
    pub n_requests_seen: usize,
    pub action:          ActionKind,
    pub timestamp:       DateTime<Utc>,
    pub ground_truth:    Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementAction {
    pub action_type:       ActionKind,
    pub account_id:        Option<String>,
    pub cluster_id:        Option<u32>,
    pub affected_accounts: Vec<String>,
    pub reason:            String,
    pub evidence:          Vec<String>,
    pub composite_score:   f32,
    pub timestamp:         DateTime<Utc>,
}

impl EnforcementAction {
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocBundle {
    pub cluster_id:             u32,
    pub ip_addresses:           Vec<String>,
    pub ip_subnets:             Vec<String>,
    pub payment_hashes:         Vec<String>,
    pub ja3_hashes:             Vec<String>,
    pub header_order_hashes:    Vec<String>,
    pub account_ids:            Vec<String>,
    pub country_codes:          Vec<String>,
    pub first_seen:             DateTime<Utc>,
    pub last_seen:              DateTime<Utc>,
    pub total_requests:         u64,
    pub targeted_capabilities:  Vec<String>,
    pub confidence:             f32,
    pub timestamp:              DateTime<Utc>,
}
