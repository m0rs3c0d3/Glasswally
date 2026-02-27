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
    pub pid: u32,
    pub tid: u32,
    pub fd: i32,
    pub direction: u8, // 0=write, 1=read
    pub buf_len: u32,
    pub buf: [u8; MAX_BUF],
}

/// Direction of SSL data capture
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslDirection {
    Write, // outbound — API request (prompt)
    Read,  // inbound  — API response
}

impl From<u8> for SslDirection {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Read,
            _ => Self::Write,
        }
    }
}

/// Raw TCP connection event from kernel.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct RawConnEvent {
    pub pid: u32,
    pub fd: i32,
    pub src_ip: u32, // network byte order
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub kind: u8, // 0=connect, 1=close
}

// ── Parsed / enriched events ──────────────────────────────────────────────────

/// Parsed SSL event — text extracted, pid correlated to account.
#[derive(Debug, Clone)]
pub struct SslCapture {
    pub pid: u32,
    pub fd: i32,
    pub direction: SslDirection,
    pub text: String, // UTF-8 decoded (lossy)
    pub timestamp: DateTime<Utc>,
    pub account_id: Option<String>, // correlated from pid→account map
    pub conn_key: Option<ConnKey>,
}

/// TCP connection 5-tuple — used to correlate SSL events with accounts.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl std::fmt::Display for ConnKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} → {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

/// HTTP request reconstructed from SSL captures.
/// Multiple SSL events may be needed to reconstruct one HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub conn_key: Option<ConnKey>,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>, // in arrival order (for header fingerprint)
    pub body: String,
    pub timestamp: DateTime<Utc>,
    pub account_id: Option<String>,
    pub model: Option<String>,  // extracted from path or body
    pub prompt: Option<String>, // extracted from JSON body
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
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

// ── HTTP/2 SETTINGS frame fingerprint ────────────────────────────────────────
// Every HTTP/2 client sends a SETTINGS frame with fixed defaults per library.
// python-httpx, Go net/http2, curl, Chrome all ship with distinct values.

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct H2Settings {
    pub header_table_size: u32,
    pub enable_push: u8,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
    /// SHA256[:8] over all SETTINGS values — canonical fingerprint string.
    pub fingerprint: String,
}

impl H2Settings {
    pub fn compute_fingerprint(&mut self) {
        use sha2::{Digest, Sha256};
        let canonical = format!(
            "{},{},{:?},{},{},{:?}",
            self.header_table_size,
            self.enable_push,
            self.max_concurrent_streams,
            self.initial_window_size,
            self.max_frame_size,
            self.max_header_list_size,
        );
        let mut h = Sha256::new();
        h.update(canonical.as_bytes());
        self.fingerprint = hex::encode(&h.finalize()[..8]);
    }
}

// ── TLS library identification ────────────────────────────────────────────────

/// Which TLS library is the client using — detected from uprobe symbol path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TlsLibrary {
    #[default]
    Unknown,
    OpenSsl,   // libssl.so — most Python/Ruby/Node clients
    BoringSSL, // Chrome, some Go programs, android
    Nss,       // Firefox, curl on some distros
    GoTls,     // Go crypto/tls — pure-Go, no libssl
}

impl std::fmt::Display for TlsLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::OpenSsl => write!(f, "openssl"),
            Self::BoringSSL => write!(f, "boringssl"),
            Self::Nss => write!(f, "nss"),
            Self::GoTls => write!(f, "go_tls"),
        }
    }
}

// ── Canary token ───────────────────────────────────────────────────────────────
// Unique tokens embedded in responses to high-risk accounts.
// If a token appears in a scraped dataset / future training request →
// distillation confirmed and the source campaign is attributed.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryToken {
    pub token: String, // unique 32-char hex string
    pub account_id: String,
    pub request_id: String,
    pub inserted_at: DateTime<Utc>,
    pub triggered: bool, // true once token seen in inbound request
    pub trigger_ts: Option<DateTime<Utc>>,
}

impl CanaryToken {
    pub fn generate(account_id: &str, request_id: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"gw_canary:");
        h.update(account_id.as_bytes());
        h.update(b":");
        h.update(request_id.as_bytes());
        h.update(Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        let token = hex::encode(&h.finalize()[..16]);
        Self {
            token,
            account_id: account_id.to_string(),
            request_id: request_id.to_string(),
            inserted_at: Utc::now(),
            triggered: false,
            trigger_ts: None,
        }
    }
}

// ── Parsed API event ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEvent {
    pub request_id: String,
    pub account_id: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: IpAddr,
    pub user_agent: String,
    pub model: String,
    pub prompt: String,
    pub token_count: u32,
    pub payment_method_hash: Option<String>,
    pub org_id: Option<String>,
    pub country_code: String,
    pub header_order: Vec<String>, // from eBPF HTTP reconstruction
    pub ja3_hash: Option<String>,  // TLS ClientHello fingerprint
    pub ja3s_hash: Option<String>, // TLS ServerHello fingerprint (Tier 1)
    pub h2_settings: Option<H2Settings>, // HTTP/2 SETTINGS frame (Tier 2)
    pub tls_library: Option<TlsLibrary>, // detected TLS implementation
    pub asn_number: Option<u32>,   // BGP ASN of source IP (Phase 1)
    pub asn_org: Option<String>,   // ASN org name (e.g. "AMAZON-AES", "AS-CHOOPA")
    pub max_tokens: Option<u32>,   // requested max_tokens from API body
    pub system_prompt_hash: Option<String>, // SHA256[:8] of system prompt / role preamble
    pub campaign_label: Option<String>,
}

// ── Detection types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WorkerKind {
    // Core detectors
    Fingerprint, // JA3 mismatch + HTTP header entropy
    Velocity,    // RPH / timing regularity
    Cot,         // Aho-Corasick CoT elicitation patterns
    Semantic,    // legacy; use Embed
    Hydra,       // cluster graph scoring
    Pivot,       // coordinated model switch
    // Tier 1 (original)
    Watermark,     // response watermark probe detection
    Embed,         // semantic similarity — paraphrase-resistant CoT
    TimingCluster, // cross-account synchronized burst detection
    // Tier 2 (original)
    H2Grpc,    // HTTP/2 SETTINGS + gRPC fingerprinting
    Biometric, // behavioral sequence entropy
    // Phase 1 — new signals
    AsnClassifier, // datacenter/hosting provider IP classification
    RolePreamble,  // role injection preamble fingerprinting
    SessionGap,    // inter-session timing regularity (cron detection)
    TokenBudget,   // max_tokens sweep / greedy budget probing
    RefusalProbe,  // safety refusal probe pattern detection
    // Phase 3
    SequenceModel, // Markov chain over prompt topic transitions
}

impl std::fmt::Display for WorkerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fingerprint => write!(f, "fingerprint"),
            Self::Velocity => write!(f, "velocity"),
            Self::Cot => write!(f, "cot"),
            Self::Semantic => write!(f, "semantic"),
            Self::Hydra => write!(f, "hydra"),
            Self::Pivot => write!(f, "pivot"),
            Self::Watermark => write!(f, "watermark"),
            Self::Embed => write!(f, "embed"),
            Self::TimingCluster => write!(f, "timing_cluster"),
            Self::H2Grpc => write!(f, "h2_grpc"),
            Self::Biometric => write!(f, "biometric"),
            Self::AsnClassifier => write!(f, "asn_classifier"),
            Self::RolePreamble => write!(f, "role_preamble"),
            Self::SessionGap => write!(f, "session_gap"),
            Self::TokenBudget => write!(f, "token_budget"),
            Self::RefusalProbe => write!(f, "refusal_probe"),
            Self::SequenceModel => write!(f, "sequence_model"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSignal {
    pub worker: WorkerKind,
    pub account_id: String,
    pub score: f32,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub meta: HashMap<String, serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionKind {
    Monitor,
    RateLimit,
    FlagForReview,
    SuspendAccount,
    ClusterTakedown,
    IntelShare,
    InjectCanary, // mark account for response watermarking + canary injection
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Monitor => write!(f, "MONITOR"),
            Self::RateLimit => write!(f, "RATE_LIMIT"),
            Self::FlagForReview => write!(f, "FLAG_FOR_REVIEW"),
            Self::SuspendAccount => write!(f, "SUSPEND_ACCOUNT"),
            Self::ClusterTakedown => write!(f, "CLUSTER_TAKEDOWN"),
            Self::IntelShare => write!(f, "INTEL_SHARE"),
            Self::InjectCanary => write!(f, "INJECT_CANARY"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDecision {
    pub account_id: String,
    pub composite_score: f32,
    pub tier: RiskTier,
    pub signal_scores: HashMap<String, f32>,
    pub top_evidence: Vec<String>,
    pub country_codes: Vec<String>,
    pub cluster_id: Option<u32>,
    pub n_requests_seen: usize,
    pub action: ActionKind,
    pub timestamp: DateTime<Utc>,
    pub ground_truth: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementAction {
    pub action_type: ActionKind,
    pub account_id: Option<String>,
    pub cluster_id: Option<u32>,
    pub affected_accounts: Vec<String>,
    pub reason: String,
    pub evidence: Vec<String>,
    pub composite_score: f32,
    pub canary_token: Option<CanaryToken>, // set when action_type == InjectCanary
    pub timestamp: DateTime<Utc>,
}

impl EnforcementAction {
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocBundle {
    pub cluster_id: u32,
    pub ip_addresses: Vec<String>,
    pub ip_subnets: Vec<String>,
    pub payment_hashes: Vec<String>,
    pub ja3_hashes: Vec<String>,
    pub ja3s_hashes: Vec<String>, // Tier 1: server-hello fingerprints
    pub header_order_hashes: Vec<String>,
    pub h2_fingerprints: Vec<String>, // Tier 2: HTTP/2 SETTINGS fingerprints
    pub watermark_tokens: Vec<String>, // triggered canary tokens
    pub account_ids: Vec<String>,
    pub country_codes: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub total_requests: u64,
    pub targeted_capabilities: Vec<String>,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
}
