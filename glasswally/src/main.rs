// glasswally/src/main.rs
//
// Glasswally — Real-time LLM distillation attack detection via eBPF
//
// Three operational modes:
//   ebpf    — live kernel uprobes on ssl_write/ssl_read (Linux 5.8+, production)
//   tail    — tail a JSONL API gateway log file (any platform, staging)
//   replay  — replay a captured log at scaled speed (testing/research)
//
// Usage:
//   sudo glasswally --mode ebpf                            # live eBPF
//   glasswally --mode tail --path /var/log/api/access.jsonl
//   glasswally --mode replay --path captured.jsonl --speed 10.0

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod engine;
mod events;
mod http_reconstruct;
mod ioc_feed;
mod loader;
mod redteam;
mod state;
mod workers;

use engine::{dispatcher::Dispatcher, fusion::FusionEngine};
use events::{ActionKind, ApiEvent, RiskTier};
use state::window::StateStore;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name    = "glasswally",
    about   = "Real-time LLM distillation attack detection via eBPF",
    version = env!("CARGO_PKG_VERSION"),
)]
struct Cli {
    #[arg(long, value_enum, default_value = "tail")]
    mode: Mode,

    #[arg(long, default_value = "/tmp/glasswally_feed.jsonl",
          help = "JSONL log path (tail/replay modes)")]
    path: PathBuf,

    #[arg(long, default_value = "1.0", help = "Replay speed multiplier")]
    speed: f64,

    #[arg(long, default_value = "/tmp/glasswally_output",
          help = "Enforcement output directory")]
    output: PathBuf,

    #[arg(long, default_value = "443", help = "TLS port for eBPF mode")]
    port: u16,
}

#[derive(Clone, ValueEnum)]
enum Mode {
    Ebpf,    // live kernel uprobes (Linux 5.8+, requires CAP_BPF or root)
    Tail,    // tail a live JSONL log file
    Replay,  // replay a static JSONL file at scaled speed
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

struct Pipeline {
    store:      Arc<StateStore>,
    engine:     Arc<FusionEngine>,
    dispatcher: Arc<Dispatcher>,
}

impl Pipeline {
    fn new(output: PathBuf) -> Self {
        Self {
            store:      Arc::new(StateStore::new()),
            engine:     Arc::new(FusionEngine::new()),
            dispatcher: Arc::new(Dispatcher::new(output)),
        }
    }

    async fn process(&self, event: ApiEvent) {
        // Ingest into sliding windows + indexes
        self.store.ingest(&event);

        // Run all workers concurrently
        let signals = workers::run_all(&event, &self.store).await;

        // Fuse signals
        let decision = match self.engine.fuse(&event, &self.store, &signals) {
            Some(d) => d,
            None    => return,
        };

        if !self.engine.should_alert(&event.account_id) { return; }

        // Dispatch enforcement action
        match self.dispatcher.dispatch(&decision, &self.store).await {
            Ok(action) => {
                self.engine.record_alert(
                    &event.account_id,
                    decision.tier == RiskTier::Critical,
                );
                print_alert(&decision, &action.action_type);
            }
            Err(e) => error!("Dispatch failed: {}", e),
        }
    }
}

// ── Terminal output ───────────────────────────────────────────────────────────

fn print_banner() {
    println!("\x1b[1m");
    println!("  ██████╗ ██╗      █████╗ ███████╗███████╗██╗    ██╗ █████╗ ██╗     ██╗  ██╗   ██╗");
    println!(" ██╔════╝ ██║     ██╔══██╗██╔════╝██╔════╝██║    ██║██╔══██╗██║     ██║  ╚██╗ ██╔╝");
    println!(" ██║  ███╗██║     ███████║███████╗███████╗██║ █╗ ██║███████║██║     ██║   ╚████╔╝ ");
    println!(" ██║   ██║██║     ██╔══██║╚════██║╚════██║██║███╗██║██╔══██║██║     ██║    ╚██╔╝  ");
    println!(" ╚██████╔╝███████╗██║  ██║███████║███████║╚███╔███╔╝██║  ██║███████╗███████╗██║   ");
    println!("  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ");
    println!("\x1b[0m");
    println!("  \x1b[90mReal-time LLM distillation attack detection | eBPF + Rust\x1b[0m");
    println!("  \x1b[90mgithub.com/m0rs3c0d3/glasswally\x1b[0m\n");
}

fn print_alert(decision: &events::RiskDecision, action: &ActionKind) {
    let (color, icon) = match decision.tier {
        RiskTier::Critical => ("\x1b[91;1m", "🔴"),
        RiskTier::High     => ("\x1b[93;1m", "🟡"),
        RiskTier::Medium   => ("\x1b[96m",   "🔵"),
        RiskTier::Low      => ("\x1b[92m",   "🟢"),
    };
    let reset = "\x1b[0m";
    let ev    = decision.top_evidence.iter().take(3).cloned().collect::<Vec<_>>().join(" | ");
    let gt    = decision.ground_truth.as_deref().map(|g| format!(" \x1b[90m[{}]{}", g, reset)).unwrap_or_default();

    println!("\n{}{} {} → {}{}",   color, icon, decision.tier, action, reset);
    println!("  Account : {}{}{}", color, decision.account_id, reset);
    println!("  Score   : {}{:.4}{}", color, decision.composite_score, reset);
    println!("  Cluster : {:?}", decision.cluster_id);
    println!("  Evidence: {}{}", ev, gt);
}

async fn print_stats_loop(store: Arc<StateStore>, start: Instant) {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let elapsed = start.elapsed().as_secs_f64();
        let events  = store.total_events.load(std::sync::atomic::Ordering::Relaxed);
        println!(
            "\n\x1b[1m── stats  uptime={:.0}s  events={}  eps={:.1}  accounts={}  clusters={} ──\x1b[0m",
            elapsed, events, events as f64 / elapsed,
            store.n_accounts(), store.n_clusters()
        );
    }
}

// ── Event sources ─────────────────────────────────────────────────────────────

async fn tail_jsonl(path: PathBuf, tx: mpsc::Sender<ApiEvent>, seek_end: bool) -> Result<()> {
    let file   = tokio::fs::File::open(&path).await?;
    let mut lines = BufReader::new(file).lines();

    if seek_end {
        while lines.next_line().await?.is_some() {}  // consume existing
    }

    info!("Tailing {}", path.display());
    loop {
        match lines.next_line().await? {
            Some(line) => {
                let line = line.trim().to_string();
                if line.is_empty() { continue; }
                match serde_json::from_str::<ApiEvent>(&line) {
                    Ok(ev) => { if tx.send(ev).await.is_err() { break; } }
                    Err(e) => warn!("Parse error: {}", e),
                }
            }
            None => tokio::time::sleep(tokio::time::Duration::from_millis(50)).await,
        }
    }
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive("glasswally=info".parse()?))
        .compact().init();

    let cli      = Cli::parse();
    let pipeline = Arc::new(Pipeline::new(cli.output.clone()));
    let start    = Instant::now();
    let (tx, mut rx) = mpsc::channel::<ApiEvent>(16384);

    print_banner();

    // Stats printer
    let store_stats = Arc::clone(&pipeline.store);
    tokio::spawn(print_stats_loop(store_stats, start));

    // Housekeeping
    let store_hk = Arc::clone(&pipeline.store);
    tokio::spawn(store_hk.housekeeping_loop());

    // Event source
    let tx2 = tx.clone();
    match cli.mode {
        Mode::Ebpf => {
            println!("  Mode: \x1b[91;1meBPF\x1b[0m  |  Attaching kernel uprobes...");
            println!("  \x1b[90mRequires: Linux 5.8+, CAP_BPF or root\x1b[0m\n");

            // In full production build (--features live-ebpf):
            //   let loader  = loader::GlasswallLoader::load()?;
            //   let mut rx_ssl = loader.attach_and_stream().await?;
            //   // Reconstruct HTTP from SSL plaintext + convert to ApiEvent
            //   tokio::spawn(async move {
            //       let mut reassembler = http_reconstruct::StreamReassembler::new();
            //       while let Some(capture) = rx_ssl.recv().await {
            //           if let Some(req) = reassembler.feed(capture) {
            //               if let Some(ev) = api_event_from_request(req) {
            //                   tx2.send(ev).await.ok();
            //               }
            //           }
            //       }
            //   });

            eprintln!("eBPF mode requires --features live-ebpf and Linux 5.8+.");
            eprintln!("Build with: cargo xtask build-ebpf && cargo run --features live-ebpf -- --mode ebpf");
            eprintln!("\nFalling back to tail mode for this run.");
            let path = cli.path.clone();
            tokio::spawn(async move { tail_jsonl(path, tx2, false).await.ok(); });
        }

        Mode::Tail => {
            println!("  Mode: \x1b[96mTAIL\x1b[0m  |  {}", cli.path.display());
            println!("  Output: \x1b[90m{}\x1b[0m\n", cli.output.display());
            let path = cli.path.clone();
            tokio::spawn(async move { tail_jsonl(path, tx2, true).await.ok(); });
        }

        Mode::Replay => {
            println!("  Mode: \x1b[93mREPLAY\x1b[0m  |  {}  speed={:.1}x", cli.path.display(), cli.speed);
            println!("  Output: \x1b[90m{}\x1b[0m\n", cli.output.display());
            let path  = cli.path.clone();
            let speed = cli.speed;
            tokio::spawn(async move {
                replay_jsonl(path, tx2, speed).await.ok();
            });
        }
    }

    println!("  Press Ctrl+C to stop.\n");

    // Main consumer — spawn one task per event for parallelism
    while let Some(event) = rx.recv().await {
        let p = Arc::clone(&pipeline);
        tokio::spawn(async move { p.process(event).await; });
    }

    Ok(())
}

async fn replay_jsonl(path: PathBuf, tx: mpsc::Sender<ApiEvent>, speed: f64) -> Result<()> {
    let content = tokio::fs::read_to_string(&path).await?;
    let mut events: Vec<(f64, ApiEvent)> = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        if let Ok(ev) = serde_json::from_str::<ApiEvent>(line) {
            let ts = ev.timestamp.timestamp_millis() as f64;
            events.push((ts, ev));
        }
    }

    if events.is_empty() { return Ok(()); }
    events.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

    let base_ts   = events[0].0;
    let base_wall = std::time::Instant::now();

    for (ts, mut event) in events {
        let offset = ((ts - base_ts) / speed / 1000.0) as f64;
        let target = base_wall + std::time::Duration::from_secs_f64(offset);
        let now    = std::time::Instant::now();
        if target > now {
            tokio::time::sleep(target - now).await;
        }
        event.timestamp = Utc::now();
        if tx.send(event).await.is_err() { break; }
    }
    Ok(())
}
