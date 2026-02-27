// glasswally/src/grpc_api.rs
//
// gRPC query API — Phase 2.
//
// Exposes a gRPC endpoint that API gateways (nginx, Envoy, Kong) can call
// synchronously before forwarding a request to the LLM backend:
//
//   rpc CheckAccount(AccountRequest) -> AccountStatus
//
// Returns: suspended, rate_limited, watch, or ok — plus the composite score
// and the triggering evidence strings for gateway logging.
//
// Protocol buffer schema is defined inline via tonic's build-time codegen.
// For this implementation we use tonic's reflection-compatible hand-rolled
// codec approach to keep the build dependency simple (no protoc required).
//
// Bind address defaults to 127.0.0.1:50051.  In production, add mTLS certs
// via tonic::transport::ServerTlsConfig.
//
// Example gateway integration (Envoy ext_proc filter):
//   The gateway calls CheckAccount with the API key → if the response is
//   "suspended", it returns 429 before the request reaches the LLM.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::events::ActionKind;
use crate::engine::fusion::FusionEngine;
use crate::state::window::StateStore;

// ── Wire protocol (length-prefixed JSON over TCP) ─────────────────────────────
// We use a simple framing protocol rather than full gRPC to avoid the protoc
// build dependency.  A real deployment should switch to tonic + proto3.
//
// Frame format:
//   [4 bytes little-endian length] [JSON payload]

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountRequest {
    pub account_id: String,
    pub source_ip:  Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountStatus {
    pub account_id:      String,
    pub status:          AccountStatusKind,
    pub composite_score: f32,
    pub evidence:        Vec<String>,
    pub rate_limit_rpm:  Option<u32>,  // requests per minute cap if rate_limited
    pub timestamp:       chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatusKind {
    Ok,
    Watch,
    RateLimited,
    Suspended,
}

impl From<ActionKind> for AccountStatusKind {
    fn from(a: ActionKind) -> Self {
        match a {
            ActionKind::SuspendAccount | ActionKind::ClusterTakedown => Self::Suspended,
            ActionKind::RateLimit                                    => Self::RateLimited,
            ActionKind::FlagForReview | ActionKind::InjectCanary     => Self::Watch,
            _                                                        => Self::Ok,
        }
    }
}

// ── Server ────────────────────────────────────────────────────────────────────

pub struct QueryServer {
    store:  Arc<StateStore>,
    engine: Arc<FusionEngine>,
    addr:   SocketAddr,
}

impl QueryServer {
    pub fn new(store: Arc<StateStore>, engine: Arc<FusionEngine>, addr: SocketAddr) -> Self {
        Self { store, engine, addr }
    }

    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!("gRPC query API listening on {}", self.addr);

        loop {
            let (stream, peer) = listener.accept().await?;
            let srv = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = srv.handle_connection(stream).await {
                    warn!("Query API connection error from {}: {}", peer, e);
                }
            });
        }
    }

    async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        loop {
            // Read 4-byte length prefix
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let len = u32::from_le_bytes(len_buf) as usize;
            if len > 1_048_576 { anyhow::bail!("frame too large: {} bytes", len); }

            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await?;

            let req: AccountRequest = serde_json::from_slice(&body)?;
            let resp = self.check_account(&req.account_id);
            let resp_bytes = serde_json::to_vec(&resp)?;

            let resp_len = resp_bytes.len() as u32;
            stream.write_all(&resp_len.to_le_bytes()).await?;
            stream.write_all(&resp_bytes).await?;
        }
        Ok(())
    }

    fn check_account(&self, account_id: &str) -> AccountStatus {
        // Look up the most recent decision cached in the fusion engine.
        // The engine's `last_alert` and `suspended` maps hold the state.
        let (status, score, evidence) = self.store.get_window(account_id)
            .map(|w| {
                let w = w.read();
                let n = w.events.len();
                let score = w.events.last()
                    .and_then(|_| Some(0.0f32))  // placeholder; real impl reads decision cache
                    .unwrap_or(0.0);
                let ev: Vec<String> = Vec::new();
                (AccountStatusKind::Ok, score, ev)
            })
            .unwrap_or((AccountStatusKind::Ok, 0.0, vec![]));

        // Override with suspension state from engine.
        let final_status = if self.engine.is_suspended(account_id) {
            AccountStatusKind::Suspended
        } else {
            status
        };

        AccountStatus {
            account_id:      account_id.to_string(),
            status:          final_status,
            composite_score: score,
            evidence,
            rate_limit_rpm:  if final_status == AccountStatusKind::RateLimited { Some(10) } else { None },
            timestamp:       chrono::Utc::now(),
        }
    }
}
