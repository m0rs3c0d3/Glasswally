// glasswally/src/workers/asn_classifier.rs
//
// ASN / hosting provider classification — Phase 1 signal.
//
// Legitimate individual API users connect from residential ISPs, university
// networks, or corporate VPNs.  Distillation campaigns use cloud compute
// (AWS, GCP, Azure, Hetzner, OVH, Vultr, DigitalOcean, Linode, Choopa/Vultr)
// to run batch inference jobs at scale.
//
// Two complementary signals:
//
//  1. INDIVIDUAL ACCOUNT — source ASN is a known datacenter/cloud provider.
//     Score uplift proportional to provider risk tier.
//
//  2. CLUSTER — ≥60% of cluster accounts originate from cloud ASNs.
//     "Cloud cluster" is a near-certain sign of coordinated automation.
//
// ASN enrichment:
//   In production the asn_number + asn_org fields on ApiEvent are populated by
//   a BGP routing table lookup (e.g. ip2asn.com batch lookup, MaxMind GeoIP2,
//   or pyasn).  Here we classify by known ASN org name prefixes.
//
// Score contributions:
//   datacenter_ip_individual:   +0.25  single account on known cloud ASN
//   datacenter_ip_high_risk:    +0.15  additional (VPS/bulletproof hosters)
//   cloud_cluster:              +0.40  cluster majority on cloud ASNs
//   single_cloud_provider:      +0.10  all accounts on same cloud provider

use std::collections::HashMap;

use chrono::Utc;

use crate::events::{ApiEvent, DetectionSignal, WorkerKind};
use crate::state::window::StateStore;

// ── Known cloud / datacenter ASN org name prefixes (lowercased) ───────────────
// Tier 1 — major cloud providers (high volume legitimate use too, lower risk weight)
const CLOUD_TIER1: &[&str] = &[
    "amazon",
    "aws",
    "google",
    "gcp",
    "microsoft",
    "azure",
    "alibaba",
    "tencent cloud",
    "oracle cloud",
];

// Tier 2 — VPS / dedicated server / bulk hosters (lower legitimate use, higher risk)
const CLOUD_TIER2: &[&str] = &[
    "digitalocean",
    "linode",
    "akamai",
    "vultr",
    "choopa",
    "hetzner",
    "ovh",
    "ovhcloud",
    "online s.a.s",
    "scaleway",
    "contabo",
    "leaseweb",
    "cogent",
    "hurricane electric",
    "quadranet",
    "fiberhub",
    "frantech",
    "buyvm",
    "m247",
    "serverius",
    "serverastra",
    "datacamp",
    "hostwinds",
    "dreamhost",
    "interserver",
];

// Tier 3 — Bulletproof / known abuse-friendly hosters
const CLOUD_TIER3: &[&str] = &[
    "sharktech",
    "colocation america",
    "krypt",
    "tzulo",
    "fdcservers",
    "psychz",
    "spinservers",
    "servermania",
    "nexeon",
    "path network",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudTier {
    None,
    Major,
    Vps,
    Bulletproof,
}

fn classify_asn_org(org: &str) -> CloudTier {
    let lower = org.to_lowercase();
    if CLOUD_TIER3.iter().any(|&p| lower.contains(p)) {
        return CloudTier::Bulletproof;
    }
    if CLOUD_TIER2.iter().any(|&p| lower.contains(p)) {
        return CloudTier::Vps;
    }
    if CLOUD_TIER1.iter().any(|&p| lower.contains(p)) {
        return CloudTier::Major;
    }
    CloudTier::None
}

pub async fn analyze(event: &ApiEvent, store: &StateStore) -> Option<DetectionSignal> {
    let asn_org = event.asn_org.as_deref().unwrap_or("");
    let tier = classify_asn_org(asn_org);

    let mut score = 0.0f32;
    let mut evidence = Vec::new();

    // ── 1. Individual account ASN classification ──────────────────────────────
    match tier {
        CloudTier::Major => {
            score += 0.20;
            evidence.push(format!("datacenter_ip:cloud_major:{}", asn_org));
        }
        CloudTier::Vps => {
            score += 0.35;
            evidence.push(format!("datacenter_ip:vps_host:{}", asn_org));
        }
        CloudTier::Bulletproof => {
            score += 0.50;
            evidence.push(format!("datacenter_ip:bulletproof_host:{}", asn_org));
        }
        CloudTier::None => {}
    }

    // ── 2. Cluster-level cloud provider analysis ───────────────────────────────
    if let Some(cluster_id) = store.get_cluster(&event.account_id) {
        let members = store.cluster_members(cluster_id);
        if members.len() >= 3 {
            let mut cloud_count = 0usize;
            let mut provider_counts: HashMap<String, usize> = HashMap::new();

            for member in &members {
                if let Some(w) = store.get_window(member) {
                    let w = w.read();
                    if let Some(org) = w.events.back().and_then(|e| e.asn_org.as_deref()) {
                        if classify_asn_org(org) != CloudTier::None {
                            cloud_count += 1;
                            // Aggregate provider name (first word)
                            let provider = org
                                .split_whitespace()
                                .next()
                                .unwrap_or("unknown")
                                .to_lowercase();
                            *provider_counts.entry(provider).or_default() += 1;
                        }
                    }
                }
            }

            let cloud_frac = cloud_count as f32 / members.len() as f32;
            if cloud_frac >= 0.60 {
                score += 0.40;
                evidence.push(format!(
                    "cloud_cluster:{:.0}%_cloud_asn",
                    cloud_frac * 100.0
                ));

                // Extra signal: all on same provider
                if let Some((provider, cnt)) = provider_counts.iter().max_by_key(|e| *e.1) {
                    if *cnt as f32 / members.len() as f32 >= 0.70 {
                        score += 0.10;
                        evidence.push(format!(
                            "single_cloud_provider:{}:{}_accounts",
                            provider, cnt
                        ));
                    }
                }
            }
        }
    }

    if score < 0.15 {
        return None;
    }

    let confidence = match tier {
        CloudTier::Bulletproof => 0.90,
        CloudTier::Vps => 0.80,
        CloudTier::Major => 0.60,
        CloudTier::None => 0.70, // cluster-only signal
    };

    let mut meta = HashMap::new();
    if let Some(asn) = event.asn_number {
        meta.insert(
            "asn".to_string(),
            serde_json::Value::Number(serde_json::Number::from(asn as u64)),
        );
    }
    meta.insert(
        "asn_org".to_string(),
        serde_json::Value::String(asn_org.to_string()),
    );
    meta.insert(
        "cloud_tier".to_string(),
        serde_json::Value::String(format!("{:?}", tier)),
    );

    Some(DetectionSignal {
        worker: WorkerKind::AsnClassifier,
        account_id: event.account_id.clone(),
        score: score.min(1.0),
        confidence,
        evidence,
        meta,
        timestamp: Utc::now(),
    })
}
