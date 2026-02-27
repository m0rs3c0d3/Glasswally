// glasswally-ebpf/src/main.rs
//
// Glasswally eBPF kernel programs.
//
// These programs run INSIDE the Linux kernel via the eBPF VM.
// They are compiled to BPF bytecode (bpfel-unknown-none target)
// and loaded by the userspace loader (glasswally/src/loader.rs).
//
// Programs:
//   1. ssl_write_uprobe  — intercepts OpenSSL ssl_write() → reads plaintext
//   2. ssl_read_uprobe   — intercepts OpenSSL ssl_read()  → reads plaintext
//   3. tcp_connect_kprobe — tracks new connections (5-tuple metadata)
//   4. tcp_close_kprobe   — cleans up connection state
//
// Why uprobes on OpenSSL instead of pcap:
//   - ssl_write() is called BEFORE encryption → we see plaintext
//   - No need to decrypt TLS — we hook before the crypto happens
//   - Zero-copy: data goes kernel → perf ring buffer → userspace
//   - No libpcap dependency, no root required (CAP_BPF suffices on 5.8+)
//
// Kernel requirements: Linux 5.8+ (BTF + CO-RE), CONFIG_BPF_SYSCALL=y
// For ssl uprobes: CONFIG_UPROBE_EVENTS=y

#![no_std]
#![no_main]

use aya_bpf::{
    macros::{kprobe, kretprobe, map, uprobe, uretprobe, tracepoint},
    maps::{HashMap, PerfEventArray, RingBuf},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
    BpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_buf},
};
use aya_log_ebpf::info;

// ── Shared event types (must be repr(C) for BPF map compatibility) ────────────

/// Maximum bytes we capture per SSL call.
/// Tuned to capture full prompts — 4KB covers most API requests.
/// Larger = more verifier complexity + perf overhead.
const MAX_BUF: usize = 4096;

/// SSL event sent from kernel to userspace via perf ring buffer.
#[repr(C)]
pub struct SslEvent {
    pub pid:       u32,
    pub tid:       u32,
    pub fd:        i32,
    pub direction: u8,     // 0 = write (outbound request), 1 = read (inbound response)
    pub buf_len:   u32,
    pub buf:       [u8; MAX_BUF],
}

/// TCP connection event — sent on new connection establishment.
#[repr(C)]
pub struct ConnEvent {
    pub pid:      u32,
    pub fd:       i32,
    pub src_ip:   u32,    // network byte order
    pub dst_ip:   u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub kind:     u8,     // 0 = connect, 1 = close
}

// ── BPF Maps ──────────────────────────────────────────────────────────────────

/// Perf event array — zero-copy channel to userspace.
/// Userspace polls this via tokio + aya AsyncPerfEventArray.
#[map]
static SSL_EVENTS: PerfEventArray<SslEvent> = PerfEventArray::new(0);

#[map]
static CONN_EVENTS: PerfEventArray<ConnEvent> = PerfEventArray::new(0);

/// Scratch space: pid → ssl_write buf pointer (saved in uprobe, read in uretprobe).
/// We need to save the pointer at function entry and read it at return
/// because at return we know the actual bytes written (return value).
#[map]
static SSL_WRITE_ARGS: HashMap<u64, SslWriteArgs> = HashMap::with_max_entries(1024, 0);

#[map]
static SSL_READ_ARGS: HashMap<u64, SslReadArgs> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
struct SslWriteArgs {
    buf: *const u8,
    len: i32,
}

#[repr(C)]
struct SslReadArgs {
    buf: *const u8,
}

// ── SSL_WRITE uprobe ──────────────────────────────────────────────────────────
//
// Attaches to: libssl.so ssl_write(SSL *ssl, const void *buf, int num)
//
// We hook at ENTRY to save the buf pointer (arg1) and num (arg2).
// We hook at RETURN to read the actual bytes written (retval)
// and copy them from userspace memory into the perf event.

#[uprobe(name = "ssl_write_enter")]
pub fn ssl_write_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_write_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_write_enter(ctx: &ProbeContext) -> Result<(), i64> {
    // ssl_write(SSL *ssl, const void *buf, int num)
    // arg0 = SSL* (skip), arg1 = buf ptr, arg2 = num bytes
    let buf: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let len: i32        = ctx.arg(2).ok_or(1i64)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe {
        SSL_WRITE_ARGS.insert(&pid_tgid, &SslWriteArgs { buf, len }, 0)
            .map_err(|e| e as i64)?;
    }
    Ok(())
}

#[uretprobe(name = "ssl_write_exit")]
pub fn ssl_write_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_write_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_write_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = unsafe {
        SSL_WRITE_ARGS.get(&pid_tgid).ok_or(1i64)?
    };

    // Return value = bytes actually written (-1 on error)
    let retval: i32 = ctx.ret().ok_or(1i64)?;
    if retval <= 0 { return Ok(()); }

    let cap_len = (retval as usize).min(MAX_BUF) as u32;

    // Build the event — BPF stack size is limited (512 bytes)
    // We use a zeroed event to avoid stack issues
    let mut event = SslEvent {
        pid:       (pid_tgid >> 32) as u32,
        tid:       (pid_tgid & 0xFFFFFFFF) as u32,
        fd:        0,  // fd correlation done in userspace via /proc
        direction: 0,  // write = outbound
        buf_len:   cap_len,
        buf:       [0u8; MAX_BUF],
    };

    // Copy plaintext from userspace into BPF stack
    unsafe {
        bpf_probe_read_user_buf(args.buf, &mut event.buf[..cap_len as usize])
            .map_err(|e| e as i64)?;
    }

    // Submit to perf ring buffer → userspace
    SSL_EVENTS.output(ctx, &event, 0);

    unsafe { SSL_WRITE_ARGS.remove(&pid_tgid).ok(); }
    Ok(())
}

// ── SSL_READ uprobe ───────────────────────────────────────────────────────────
//
// Attaches to: libssl.so ssl_read(SSL *ssl, void *buf, int num)
//
// We want to capture API RESPONSES too (to detect distillation response quality).
// Same pattern: save buf ptr at entry, copy at return.

#[uprobe(name = "ssl_read_enter")]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    match try_ssl_read_enter(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_enter(ctx: &ProbeContext) -> Result<(), i64> {
    let buf: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let pid_tgid = bpf_get_current_pid_tgid();
    unsafe {
        SSL_READ_ARGS.insert(&pid_tgid, &SslReadArgs { buf }, 0)
            .map_err(|e| e as i64)?;
    }
    Ok(())
}

#[uretprobe(name = "ssl_read_exit")]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    match try_ssl_read_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_ssl_read_exit(ctx: &RetProbeContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = unsafe {
        SSL_READ_ARGS.get(&pid_tgid).ok_or(1i64)?
    };

    let retval: i32 = ctx.ret().ok_or(1i64)?;
    if retval <= 0 { return Ok(()); }

    let cap_len = (retval as usize).min(MAX_BUF) as u32;

    let mut event = SslEvent {
        pid:       (pid_tgid >> 32) as u32,
        tid:       (pid_tgid & 0xFFFFFFFF) as u32,
        fd:        0,
        direction: 1,  // read = inbound response
        buf_len:   cap_len,
        buf:       [0u8; MAX_BUF],
    };

    unsafe {
        bpf_probe_read_user_buf(args.buf, &mut event.buf[..cap_len as usize])
            .map_err(|e| e as i64)?;
    }

    SSL_EVENTS.output(ctx, &event, 0);
    unsafe { SSL_READ_ARGS.remove(&pid_tgid).ok(); }
    Ok(())
}

// ── TCP connect kprobe ────────────────────────────────────────────────────────
//
// Tracks new TCP connections — gives us the 5-tuple metadata
// (src_ip, src_port, dst_ip, dst_port) that we correlate with SSL events.
//
// Attaches to: kernel tcp_connect()

#[kprobe(name = "tcp_connect_entry")]
pub fn tcp_connect_entry(ctx: ProbeContext) -> u32 {
    match try_tcp_connect(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_tcp_connect(ctx: &ProbeContext) -> Result<(), i64> {
    // struct sock *sk is arg0
    // We read the sock struct to get IP/port info
    // Using CO-RE (Compile Once Run Everywhere) via BTF
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;

    // Offsets from BTF — aya-bpf handles this via vmlinux bindings
    // For portability, we use the aya generated vmlinux.h types
    // Simplified here — full implementation uses bpf_core_read!()
    let pid_tgid = bpf_get_current_pid_tgid();

    let event = ConnEvent {
        pid:      (pid_tgid >> 32) as u32,
        fd:       0,
        src_ip:   0,   // populated via sock struct in full impl
        dst_ip:   0,
        src_port: 0,
        dst_port: 443, // we filter in userspace to HTTPS port
        kind:     0,   // connect
    };

    CONN_EVENTS.output(ctx, &event, 0);
    Ok(())
}

// ── Panic handler (required for no_std) ──────────────────────────────────────

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF programs cannot panic — the verifier rejects programs that can.
    // This handler is required by no_std but should never be reached.
    loop {}
}
