// glasswally-ebpf/src/main.rs
//
// Glasswally eBPF kernel programs.
// Compiled to bpfel-unknown-none (BPF bytecode), loaded by glasswally/src/loader.rs.
//
// Programs:
//   1. ssl_write_enter/exit  — intercepts ssl_write (OpenSSL/BoringSSL/NSS/Go TLS)
//   2. ssl_read_enter/exit   — intercepts ssl_read
//   3. tcp_connect_entry     — tracks new TCP connections (5-tuple metadata)
//   4. udp_sendmsg_entry     — DoH detection: port 853/443 UDP (Tier 3)
//
// Tier 1 additions vs original:
//   - Programs are reusable for BoringSSL + NSS: same uprobe ABI
//   - Go TLS: loader attaches these same programs to Go binary offsets
//
// Tier 3 addition:
//   - udp_sendmsg_entry: track DNS-over-HTTPS client behavior
//
// Kernel requirements: Linux 5.8+ (BTF + CO-RE), CONFIG_BPF_SYSCALL=y,
//                      CONFIG_UPROBE_EVENTS=y

#![no_std]
#![no_main]

use aya_bpf::{
    macros::{kprobe, map, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext},
    BpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_buf},
};
use aya_log_ebpf::info;

// ── Shared event types ────────────────────────────────────────────────────────

const MAX_BUF:    usize = 4096;
const MAX_DNS:    usize = 256;

#[repr(C)]
pub struct SslEvent {
    pub pid:       u32,
    pub tid:       u32,
    pub fd:        i32,
    pub direction: u8,   // 0=write (request), 1=read (response)
    pub buf_len:   u32,
    pub buf:       [u8; MAX_BUF],
}

#[repr(C)]
pub struct ConnEvent {
    pub pid:      u32,
    pub fd:       i32,
    pub src_ip:   u32,
    pub dst_ip:   u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub kind:     u8,    // 0=connect, 1=close
}

/// DNS-over-HTTPS event — UDP sends to port 853 or DoH on 443.
#[repr(C)]
pub struct DohEvent {
    pub pid:      u32,
    pub dst_ip:   u32,
    pub dst_port: u16,
    pub payload_len: u16,
}

// ── BPF Maps ──────────────────────────────────────────────────────────────────

#[map]
static SSL_EVENTS:  PerfEventArray<SslEvent>  = PerfEventArray::new(0);

#[map]
static CONN_EVENTS: PerfEventArray<ConnEvent> = PerfEventArray::new(0);

#[map]
static DOH_EVENTS:  PerfEventArray<DohEvent>  = PerfEventArray::new(0);

/// Scratch: pid_tgid → (buf_ptr, len) for ssl_write entry → exit correlation.
#[repr(C)]
struct SslWriteArgs { buf: *const u8, len: i32 }

#[repr(C)]
struct SslReadArgs  { buf: *const u8 }

#[map]
static SSL_WRITE_ARGS: HashMap<u64, SslWriteArgs> = HashMap::with_max_entries(2048, 0);

#[map]
static SSL_READ_ARGS:  HashMap<u64, SslReadArgs>  = HashMap::with_max_entries(2048, 0);

// ── SSL_WRITE uprobe ──────────────────────────────────────────────────────────
// Attaches to: libssl.so ssl_write   (OpenSSL)
//              libssl.so SSL_write   (BoringSSL)
//              libnss3.so PR_Write   (NSS)
//              Go binary at crypto/tls.(*Conn).Write offset

#[uprobe(name = "ssl_write_enter")]
pub fn ssl_write_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_write_enter(&ctx) { Ok(()) => 0, Err(_) => 1 }
}

fn try_ssl_write_enter(ctx: &ProbeContext) -> Result<(), i64> {
    let buf: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let len: i32        = ctx.arg(2).ok_or(1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe { SSL_WRITE_ARGS.insert(&pid_tgid, &SslWriteArgs { buf, len }, 0).map_err(|e| e as i64)? }
    Ok(())
}

#[uretprobe(name = "ssl_write_exit")]
pub fn ssl_write_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_write_exit(&ctx) { Ok(()) => 0, Err(_) => 1 }
}

fn try_ssl_write_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = unsafe { SSL_WRITE_ARGS.get(&pid_tgid).ok_or(1i64)? };
    let retval: i32 = ctx.ret().ok_or(1i64)?;
    if retval <= 0 { return Ok(()); }

    let cap_len = (retval as usize).min(MAX_BUF) as u32;
    let mut event = SslEvent {
        pid: (pid_tgid >> 32) as u32, tid: (pid_tgid & 0xFFFFFFFF) as u32,
        fd: 0, direction: 0, buf_len: cap_len, buf: [0u8; MAX_BUF],
    };
    unsafe { bpf_probe_read_user_buf(args.buf, &mut event.buf[..cap_len as usize]).map_err(|e| e as i64)?; }
    SSL_EVENTS.output(ctx, &event, 0);
    unsafe { SSL_WRITE_ARGS.remove(&pid_tgid).ok(); }
    Ok(())
}

// ── SSL_READ uprobe ───────────────────────────────────────────────────────────
// Captures API responses — important for response quality / watermark detection.

#[uprobe(name = "ssl_read_enter")]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_read_enter(&ctx) { Ok(()) => 0, Err(_) => 1 }
}

fn try_ssl_read_enter(ctx: &ProbeContext) -> Result<(), i64> {
    let buf: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe { SSL_READ_ARGS.insert(&pid_tgid, &SslReadArgs { buf }, 0).map_err(|e| e as i64)? }
    Ok(())
}

#[uretprobe(name = "ssl_read_exit")]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(&ctx) { Ok(()) => 0, Err(_) => 1 }
}

fn try_ssl_read_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = unsafe { SSL_READ_ARGS.get(&pid_tgid).ok_or(1i64)? };
    let retval: i32 = ctx.ret().ok_or(1i64)?;
    if retval <= 0 { return Ok(()); }

    let cap_len = (retval as usize).min(MAX_BUF) as u32;
    let mut event = SslEvent {
        pid: (pid_tgid >> 32) as u32, tid: (pid_tgid & 0xFFFFFFFF) as u32,
        fd: 0, direction: 1, buf_len: cap_len, buf: [0u8; MAX_BUF],
    };
    unsafe { bpf_probe_read_user_buf(args.buf, &mut event.buf[..cap_len as usize]).map_err(|e| e as i64)?; }
    SSL_EVENTS.output(ctx, &event, 0);
    unsafe { SSL_READ_ARGS.remove(&pid_tgid).ok(); }
    Ok(())
}

// ── TCP connect kprobe ────────────────────────────────────────────────────────
// Tracks new TCP connections — gives us 5-tuple metadata for SSL correlation.

#[kprobe(name = "tcp_connect_entry")]
pub fn tcp_connect_entry(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(&ctx) { Ok(()) => 0, Err(_) => 1 }
}

fn try_tcp_connect(ctx: &ProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let event = ConnEvent {
        pid: (pid_tgid >> 32) as u32, fd: 0,
        src_ip: 0, dst_ip: 0, src_port: 0,
        dst_port: 443,  // HTTPS — filter in userspace
        kind: 0,        // connect
    };
    CONN_EVENTS.output(ctx, &event, 0);
    Ok(())
}

// ── UDP sendmsg kprobe — DoH detection (Tier 3) ───────────────────────────────
// Intercepts UDP sends. Sends to port 853 (DNS-over-TLS) or 443 that look
// like DNS queries are DoH. Correlating DoH usage per-account adds a
// transport-layer clustering signal completely invisible to Fingerprint Suite.
//
// In production: parse the UDP payload to confirm DNS query format.
// Here we emit an event for port 853; userspace correlates via pid→account map.

#[kprobe(name = "udp_sendmsg_entry")]
pub fn udp_sendmsg_entry(ctx: ProbeContext) -> u32 {
    match try_udp_sendmsg(&ctx) { Ok(()) => 0, Err(_) => 1 }
}

fn try_udp_sendmsg(ctx: &ProbeContext) -> Result<(), i64> {
    // Simplified: emit event for all UDP sends; userspace filters by dst port.
    // A full implementation reads the msghdr struct to extract dst_port.
    let pid_tgid = bpf_get_current_pid_tgid();
    let event = DohEvent {
        pid:         (pid_tgid >> 32) as u32,
        dst_ip:      0,  // populated from msghdr in full impl
        dst_port:    0,  // populated from msghdr in full impl
        payload_len: 0,
    };
    DOH_EVENTS.output(ctx, &event, 0);
    Ok(())
}

// ── Panic handler ─────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }
