// glasswally/src/engine/dispatcher.rs
//
// Writes enforcement actions to output JSONL files.
// On CLUSTER_TAKEDOWN: suspends all cluster members + writes IOC bundle.
// Wire these files to your enforcement API / Kafka topics in production.

use anyhow::Result;
use chrono::Utc;
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::events::{ActionKind, EnforcementAction, IocBundle, RiskDecision, RiskTier};
use crate::state::window::StateStore;

pub struct Dispatcher {
    out: PathBuf,
}

impl Dispatcher {
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        let out: PathBuf = output_dir.into();
        std::fs::create_dir_all(&out).expect("Failed to create output directory");
        Self { out }
    }

    pub async fn dispatch(&self, decision: &RiskDecision, store: &StateStore) -> Result<EnforcementAction> {
        let mut action_type = decision.action;
        let mut affected    = vec![decision.account_id.clone()];

        // CLUSTER TAKEDOWN on CRITICAL tier
        if decision.tier == RiskTier::Critical {
            if let Some(cid) = decision.cluster_id {
                let members: Vec<String> = store.cluster_members(cid).into_iter().collect();
                if members.len() >= 3 {
                    action_type = ActionKind::ClusterTakedown;
                    affected    = members.clone();

                    // Build and write IOC bundle
                    let mut ips      = std::collections::HashSet::new();
                    let mut payments = std::collections::HashSet::new();
                    let mut uas      = std::collections::HashSet::new();
                    let mut ja3s     = std::collections::HashSet::new();
                    let mut hdrs     = std::collections::HashSet::new();

                    for acc in &members {
                        if let Some(w) = store.get_window(acc) {
                            let w = w.read();
                            ips.extend(w.ip_addresses.iter().cloned());
                            payments.extend(w.payment_hashes.iter().cloned());
                            uas.extend(w.user_agents.iter().cloned());
                            ja3s.extend(w.ja3_hashes.iter().cloned());
                            hdrs.extend(w.header_hashes.iter().cloned());
                        }
                    }

                    let subnets: std::collections::HashSet<String> = ips.iter().filter_map(|ip| {
                        let p: Vec<&str> = ip.split('.').collect();
                        if p.len() == 4 { Some(format!("{}.{}.{}", p[0], p[1], p[2])) }
                        else { None }
                    }).collect();

                    let ioc = IocBundle {
                        cluster_id:            cid,
                        ip_addresses:          ips.into_iter().collect(),
                        ip_subnets:            subnets.into_iter().collect(),
                        payment_hashes:        payments.into_iter().collect(),
                        ja3_hashes:            ja3s.into_iter().collect(),  // NEW
                        header_order_hashes:   hdrs.into_iter().collect(),  // NEW
                        account_ids:           members,
                        country_codes:         decision.country_codes.clone(),
                        first_seen:            Utc::now(),
                        last_seen:             Utc::now(),
                        total_requests:        decision.n_requests_seen as u64,
                        targeted_capabilities: decision.top_evidence.clone(),
                        confidence:            decision.composite_score,
                        timestamp:             Utc::now(),
                    };

                    self.write("ioc_bundles.jsonl", &(serde_json::to_string(&ioc)? + "\n")).await?;
                    info!("CLUSTER_TAKEDOWN cluster={} accounts={}", cid, affected.len());
                }
            }
        }

        let action = EnforcementAction {
            action_type,
            account_id:        Some(decision.account_id.clone()),
            cluster_id:        decision.cluster_id,
            affected_accounts: affected,
            reason:            format!("score={:.4} tier={}", decision.composite_score, decision.tier),
            evidence:          decision.top_evidence.clone(),
            composite_score:   decision.composite_score,
            timestamp:         Utc::now(),
        };

        let line = action.to_jsonl() + "\n";
        match action_type {
            ActionKind::SuspendAccount | ActionKind::ClusterTakedown =>
                self.write("enforcement_actions.jsonl", &line).await?,
            ActionKind::RateLimit =>
                self.write("rate_limit_commands.jsonl", &line).await?,
            ActionKind::FlagForReview =>
                self.write("analyst_queue.jsonl", &line).await?,
            _ => {}
        }
        self.write("audit_log.jsonl", &line).await?;

        Ok(action)
    }

    async fn write(&self, file: &str, content: &str) -> Result<()> {
        let mut f = OpenOptions::new().create(true).append(true)
            .open(self.out.join(file)).await?;
        f.write_all(content.as_bytes()).await?;
        Ok(())
    }
}
