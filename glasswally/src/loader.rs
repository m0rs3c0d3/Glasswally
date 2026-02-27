// glasswally/src/loader.rs
//
// aya BPF loader — loads compiled BPF bytecode and attaches probes.
//
// What this does:
//   1. Loads the BPF object (compiled glasswally-ebpf bytecode)
//   2. Attaches uprobes to libssl.so ssl_write / ssl_read
//   3. Attaches kprobes to kernel tcp_connect
//   4. Opens perf event arrays for async userspace reading
//   5. Returns async streams of SslCapture events
//
// Probe attachment finds the ssl_write symbol offset in libssl.so
// using /proc/self/maps to locate the library, then reads the ELF
// symbol table to find the function offset. aya handles this.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::AsyncPerfEventArray,
    programs::{KProbe, UProbe},
    util::online_cpus,
    Bpf, BpfLoader,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::events::{RawSslEvent, RawConnEvent, SslCapture, SslDirection, MAX_BUF};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Common OpenSSL library paths. We try each in order.
const LIBSSL_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    "/usr/local/lib/libssl.so.3",
    "/usr/local/ssl/lib/libssl.so",
    // BoringSSL (used by Chrome, some Go programs)
    "/usr/lib/x86_64-linux-gnu/libboringssl.so",
];

/// BoringSSL uses SSL_write / SSL_read (capital SSL)
const SSL_WRITE_SYMBOLS: &[&str] = &["ssl_write", "SSL_write"];
const SSL_READ_SYMBOLS:  &[&str] = &["ssl_read",  "SSL_read"];

// ── GlasswallLoader ───────────────────────────────────────────────────────────

pub struct GlasswallLoader {
    bpf: Bpf,
}

impl GlasswallLoader {
    /// Load BPF programs from embedded bytecode.
    /// The bytecode is compiled by `cargo xtask build-ebpf` and embedded
    /// at compile time via include_bytes_aligned!().
    pub fn load() -> Result<Self> {
        // Load BPF bytecode — compiled to bpfel (little-endian BPF)
        // In production build: uses the actual compiled BPF object
        // In dev/test: gracefully degrades to log-only mode
        
        #[cfg(feature = "live-ebpf")]
        let bpf_bytes = include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/glasswally-ebpf")
        );
        
        #[cfg(not(feature = "live-ebpf"))]
        let bpf_bytes: &[u8] = &[];

        if bpf_bytes.is_empty() {
            return Err(anyhow!(
                "BPF bytecode not embedded. Run: cargo xtask build-ebpf\n\
                 Then rebuild with: cargo build --features live-ebpf"
            ));
        }

        let bpf = BpfLoader::new()
            .load(bpf_bytes)
            .context("Failed to load BPF object")?;

        // Initialize BPF logger (routes bpf_printk to tracing)
        if let Err(e) = BpfLogger::init(&mut bpf) {
            warn!("BPF logger init failed (non-fatal): {}", e);
        }

        Ok(Self { bpf })
    }

    /// Attach all probes and return a receiver for captured SSL events.
    pub async fn attach_and_stream(
        mut self,
    ) -> Result<mpsc::Receiver<SslCapture>> {
        let (tx, rx) = mpsc::channel(65536);  // large buffer for burst traffic

        // Find libssl.so path
        let libssl = find_libssl()
            .context("Could not find libssl.so — is OpenSSL installed?")?;
        info!("Attaching uprobes to {}", libssl.display());

        // Attach ssl_write uprobe + uretprobe
        self.attach_uprobe("ssl_write_enter", &libssl, SSL_WRITE_SYMBOLS, false)?;
        self.attach_uprobe("ssl_write_exit",  &libssl, SSL_WRITE_SYMBOLS, true)?;

        // Attach ssl_read uprobe + uretprobe
        self.attach_uprobe("ssl_read_enter", &libssl, SSL_READ_SYMBOLS, false)?;
        self.attach_uprobe("ssl_read_exit",  &libssl, SSL_READ_SYMBOLS, true)?;

        // Attach tcp_connect kprobe
        let tcp_prog: &mut KProbe = self.bpf
            .program_mut("tcp_connect_entry")
            .context("tcp_connect_entry not found in BPF object")?
            .try_into()?;
        tcp_prog.load()?;
        tcp_prog.attach("tcp_connect", 0)
            .context("Failed to attach tcp_connect kprobe")?;
        info!("Attached kprobe: tcp_connect");

        // Open perf event array and spawn reader tasks
        let ssl_map: AsyncPerfEventArray<RawSslEvent> = self.bpf
            .take_map("SSL_EVENTS")
            .context("SSL_EVENTS map not found")?
            .try_into()?;

        let cpus = online_cpus().unwrap_or_else(|_| vec![0]);
        for cpu_id in cpus {
            let tx_clone = tx.clone();
            let mut buf = ssl_map.open(cpu_id, None)?;

            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(MAX_BUF + 64))
                    .collect::<Vec<_>>();

                loop {
                    let events = match buf.read_events(&mut buffers).await {
                        Ok(e) => e,
                        Err(e) => {
                            error!("Perf read error on CPU {}: {}", cpu_id, e);
                            break;
                        }
                    };

                    for buf_data in buffers.iter().take(events.read) {
                        let raw = match parse_ssl_event(buf_data) {
                            Some(r) => r,
                            None    => continue,
                        };

                        let text = String::from_utf8_lossy(
                            &raw.buf[..raw.buf_len.min(MAX_BUF as u32) as usize]
                        ).into_owned();

                        let capture = SslCapture {
                            pid:        raw.pid,
                            fd:         raw.fd,
                            direction:  SslDirection::from(raw.direction),
                            text,
                            timestamp:  Utc::now(),
                            account_id: None,   // correlated later
                            conn_key:   None,
                        };

                        if tx_clone.send(capture).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }

        info!("Glasswally eBPF probes active. Capturing SSL plaintext.");
        Ok(rx)
    }

    fn attach_uprobe(
        &mut self,
        prog_name: &str,
        lib_path:  &PathBuf,
        symbols:   &[&str],
        is_ret:    bool,
    ) -> Result<()> {
        let prog = self.bpf
            .program_mut(prog_name)
            .with_context(|| format!("{} not found in BPF object", prog_name))?;

        let uprobe: &mut UProbe = prog.try_into()?;
        uprobe.load()?;

        // Try each symbol name (ssl_write vs SSL_write)
        for &sym in symbols {
            match uprobe.attach(Some(sym), 0, lib_path, None) {
                Ok(_) => {
                    info!("Attached {}: {}:{}", prog_name, lib_path.display(), sym);
                    return Ok(());
                }
                Err(e) => {
                    warn!("Could not attach {} to {}: {}", prog_name, sym, e);
                }
            }
        }

        Err(anyhow!("Could not attach {} to any symbol in {:?}", prog_name, symbols))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn find_libssl() -> Option<PathBuf> {
    for path in LIBSSL_PATHS {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // Fallback: search /proc/self/maps for any loaded libssl
    if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
        for line in maps.lines() {
            if line.contains("libssl") {
                if let Some(path_str) = line.split_whitespace().last() {
                    let p = PathBuf::from(path_str);
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }
    }

    None
}

fn parse_ssl_event(buf: &BytesMut) -> Option<RawSslEvent> {
    if buf.len() < std::mem::size_of::<RawSslEvent>() {
        return None;
    }
    // Safe: we checked length and RawSslEvent is repr(C)
    // In production: use zerocopy or bytemuck for guaranteed safety
    let raw = unsafe {
        &*(buf.as_ptr() as *const RawSslEvent)
    };
    Some(raw.clone())
}
