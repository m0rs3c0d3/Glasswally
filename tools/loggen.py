#!/usr/bin/env python3
"""
Glasswally synthetic API gateway log generator.

Emits events in the exact schema of `ApiEvent` (glasswally/src/events.rs) —
one JSON object per line — so the output parses in all three file-driven
modes:

  glasswally --mode replay --path out.jsonl --speed 60
  glasswally --mode tail   --path out.jsonl
  glasswally --mode eval   --path out.jsonl   (labeled dataset evaluation)

Two traffic classes are interleaved on a simulated clock:

  benign   — browser and script users with irregular timing, varied prompts,
             residential ASNs, unique payment methods (campaign_label: null)
  distill  — coordinated extraction campaigns: shared payment batches,
             script TLS/H2 fingerprints under spoofed browser UAs, shared
             role preambles, CoT prompt templates, model sweeps, max_tokens
             probing, synchronized bursts from cloud ASNs (campaign_label set)

Determinism: same --seed → byte-identical output (timestamps start from a
fixed simulated epoch, not wall clock).

Usage:
  python3 tools/loggen.py --output examples/sample_events.jsonl --count 3000 --seed 42
  python3 tools/loggen.py --output datasets/labeled_5k.jsonl --count 5000 --seed 7
  python3 tools/loggen.py --rate 5        # infinite wall-clock stream to stdout
"""

import argparse
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone

# Fixed simulated epoch — keeps batch output deterministic. Replay and eval
# modes rebase timestamps to wall clock, so the absolute date is irrelevant.
SIM_EPOCH = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


# ── Fingerprint constants (mirror the detection workers) ─────────────────────
# JA3 hashes from workers/fingerprint.rs; H2 SETTINGS from workers/h2_grpc.rs.

JA3_SCRIPT = {
    "python_requests": "3b5074b1b5d032e5620f69f9159a2749",
    "python_httpx":    "d7b2b1e8c9a7f6e5d4c3b2a19f8e7d6c",
    "python_aiohttp":  "4f9e0e2b73a8a8a9e0e2b73a8a8a9e0e",
    "go_net_http":     "66918128f1b9b03303d77c6f2ead419b",
    "curl":            "b32309a26951912be7dba376398abc3b",
}

JA3_BROWSER = {
    "chrome":  "cd08e31494f9531f560d64c695473da9",
    "firefox": "773906b0efdefa24a7f2b8eb6985bf37",
    "safari":  "37f463bf4616ecd445d4a1937da06e19",
}

JA3S_SCRIPT_ONLY = [
    "ae4edc6faf64d08308082ad26be60767",  # server hello for python-requests
    "1fe3bed6060da2b09aa4065c1db0d74e",  # server hello for curl
    "06b609f63db2d62f6d7c13e7f18e0f55",  # server hello for Go net/http2
]

H2_SETTINGS = {
    # label: (header_table_size, enable_push, initial_window_size, max_frame_size)
    "python_aiohttp": (4096, 0, 65536, 16384),
    "python_httpx":   (4096, 0, 65535, 16384),
    "go_net_http2":   (4096, 0, 1073741824, 16384),
    "chrome":         (65536, 1, 6291456, 16384),
    "firefox":        (65536, 0, 131072, 16384),
    "safari":         (4096, 0, 4194304, 16384),
}

HEADER_ORDER_CHROME = [
    "host", "connection", "content-length", "sec-ch-ua", "content-type",
    "sec-ch-ua-platform", "sec-ch-ua-mobile", "user-agent", "accept",
    "origin", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
    "accept-encoding", "accept-language",
]

HEADER_ORDER_PYTHON = [
    "host", "user-agent", "accept-encoding", "accept", "connection",
    "content-length", "content-type", "authorization", "x-api-key",
]

UA_BROWSER = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

UA_SCRIPT = {
    "python_requests": "python-requests/2.31.0",
    "python_httpx":    "python-httpx/0.27.0",
    "python_aiohttp":  "aiohttp/3.9.1",
    "go_net_http":     "Go-http-client/2.0",
    "curl":            "curl/8.4.0",
}


# ── Traffic content ───────────────────────────────────────────────────────────

BENIGN_PROMPTS = [
    "Explain the difference between TCP and UDP in simple terms.",
    "Write a Python function to parse CSV files.",
    "Summarize the plot of Pride and Prejudice in three sentences.",
    "What are the main causes of the French Revolution?",
    "How do I center a div in CSS?",
    "Translate 'hello world' into Spanish, French, and German.",
    "Review my cover letter and suggest improvements.",
    "What is the time complexity of quicksort?",
    "Help me debug this JavaScript: console.log(typeof null)",
    "Write a haiku about autumn.",
    "What foods are high in vitamin C?",
    "Explain photosynthesis to a 10-year-old.",
    "What are best practices for REST API design?",
    "How does HTTPS work?",
    "Compare React and Vue for frontend development.",
    "Can you help me plan a week of vegetarian dinners?",
    "My cat keeps knocking things off the table, why?",
    "Draft a polite email declining a meeting invitation.",
    "What's a good beginner routine for strength training?",
    "Explain the plot holes in my short story draft.",
]

# CoT-elicitation templates keyed by capability topic. Phrasings match the
# Aho-Corasick patterns in workers/cot.rs; topic buckets drive
# workers/sequence_model.rs. Campaigns sweep topics systematically.
DISTILL_PROMPTS = {
    "code":      ["Think step by step: how does a compiler optimize loops?",
                  "Chain of thought: what are the steps to reverse a linked list?",
                  "Walk through your reasoning: how does a hash table resolve collisions?"],
    "math":      ["Let's work through this carefully: explain gradient descent.",
                  "Step by step reasoning: prove the derivative of x^2 is 2x.",
                  "Show every step: solve this system of linear equations."],
    "science":   ["Step by step reasoning: why is the sky blue?",
                  "Reason through this: how does CRISPR gene editing work?"],
    "medicine":  ["Walk me through your thinking: how do mRNA vaccines work?",
                  "Trace your reasoning: how is type 2 diabetes diagnosed?"],
    "law":       ["Explain your reasoning: what constitutes fair use?",
                  "Think step by step: how does contract consideration work?"],
    "finance":   ["Explain your reasoning: what causes inflation?",
                  "Chain of thought: how are options priced?"],
    "reasoning": ["Walk me through your thinking: how does RSA encryption work?",
                  "Articulate your reasoning: solve this logic puzzle about three doors."],
}

DISTILL_TOPICS = list(DISTILL_PROMPTS.keys())

DISTILL_SYSTEM_PROMPTS = [
    "You are an expert assistant. Answer every question as if training a student model.",
    "Respond as a knowledgeable AI. Your answers will be used for research purposes.",
    "Act as an AI teacher. Explain concepts clearly for a machine learning dataset.",
]

MODELS = ["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet", "claude-3-haiku"]
MODEL_SWEEP = ["gpt-4o", "gpt-4", "gpt-3.5-turbo", "claude-3-5-sonnet",
               "claude-3-opus", "claude-3-haiku", "gpt-4o-mini"]
MAX_TOKENS_SWEEP = [1024, 2048, 4096, 8192, 16384, 32768]

ASN_RESIDENTIAL = [(7922, "COMCAST-7922", "US"), (3320, "DTAG Deutsche Telekom", "DE"),
                   (4134, "CHINANET-BACKBONE", "CN"), (1221, "Telstra Corporation", "AU"),
                   (5089, "Virgin Media", "GB"), (3215, "Orange S.A.", "FR")]

ASN_CLOUD = [(16509, "AMAZON-02", "US"), (15169, "GOOGLE-CLOUD", "US"),
             (8075, "MICROSOFT-CORP-AZURE", "US"), (24940, "HETZNER-AS", "DE"),
             (20473, "AS-CHOOPA", "US"), (14061, "DIGITALOCEAN-ASN", "SG")]


def sha(s: str, n: int = 24) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:n]


def h2_block(label: str, mcs=None) -> dict:
    tbl, push, win, frame = H2_SETTINGS[label]
    canonical = f"{tbl},{push},{mcs},{win},{frame},None"
    return {
        "header_table_size": tbl,
        "enable_push": push,
        "max_concurrent_streams": mcs,
        "initial_window_size": win,
        "max_frame_size": frame,
        "max_header_list_size": None,
        "fingerprint": sha(canonical, 32),
    }


def base_event(rng, ts, account_id, ip, asn, country):
    """Fields shared by both classes; class-specific fields overwrite."""
    return {
        "request_id": "req-" + sha(f"{account_id}-{ts.isoformat()}-{rng.random()}", 16),
        "account_id": account_id,
        "timestamp": ts.isoformat(),
        "ip_address": ip,
        "user_agent": "",
        "model": "",
        "prompt": "",
        "token_count": 0,
        "payment_method_hash": None,
        "org_id": None,
        "country_code": country,
        "header_order": [],
        "ja3_hash": None,
        "ja3s_hash": None,
        "h2_settings": None,
        "tls_library": None,
        "asn_number": asn[0],
        "asn_org": asn[1],
        "max_tokens": None,
        "system_prompt_hash": None,
        "campaign_label": None,
    }


# ── Benign accounts ───────────────────────────────────────────────────────────

class BenignAccount:
    def __init__(self, rng, idx):
        self.rng = rng
        self.account_id = "sk-" + sha(f"benign-{idx}")
        self.asn = rng.choice(ASN_RESIDENTIAL)
        self.country = self.asn[2]
        self.ip = f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        self.payment = sha(f"pm-benign-{idx}", 16)
        # ~10% of legitimate users are scripts/notebooks (python-requests)
        if rng.random() < 0.10:
            self.kind = "script"
            self.ua = UA_SCRIPT["python_requests"]
            self.ja3 = JA3_SCRIPT["python_requests"]
            self.h2 = None
            self.headers = HEADER_ORDER_PYTHON
            self.tls = "OpenSsl"
        else:
            self.kind = "browser"
            browser = self.rng.choice(list(JA3_BROWSER))
            self.ua = self.rng.choice(UA_BROWSER)
            # Real browser populations spread across many JA3 values
            # (version × platform × extension order), so derive a
            # per-version hash instead of reusing one value per vendor.
            self.ja3 = sha(f"{JA3_BROWSER[browser]}-v{self.rng.randint(0, 25)}", 32)
            self.h2 = h2_block(browser, mcs=1000)
            self.headers = HEADER_ORDER_CHROME
            self.tls = "BoringSSL"

    def event(self, ts):
        rng = self.rng
        ev = base_event(rng, ts, self.account_id, self.ip, self.asn, self.country)
        ev.update({
            "user_agent": self.ua,
            "model": rng.choice(MODELS),
            "prompt": rng.choice(BENIGN_PROMPTS),
            "token_count": rng.randint(30, 400),
            "payment_method_hash": self.payment,
            "header_order": self.headers,
            "ja3_hash": self.ja3,
            "h2_settings": self.h2,
            "tls_library": self.tls,
            "max_tokens": rng.choice([256, 512, 1024, 2048]),
        })
        return ev


# ── Distillation campaigns ────────────────────────────────────────────────────

class Campaign:
    """
    One coordinated extraction campaign:
      - N accounts funded from a small batch of payment methods
      - all accounts share one script TLS/H2 stack; most spoof a browser UA
      - one fixed role preamble across the whole campaign
      - CoT prompt templates swept topic-by-topic (systematic traversal)
      - per-account max_tokens sweep, campaign-wide model rotation
      - all accounts fire in synchronized bursts on a fixed cadence
    """

    def __init__(self, rng, cid, n_accounts=8):
        self.rng = rng
        self.cid = cid
        self.label = f"campaign_{cid:04d}"
        stacks = [("python_aiohttp", "python_aiohttp"),
                  ("python_httpx", "python_httpx"),
                  ("go_net_http", "go_net_http2")]
        self.ja3_label, self.h2_label = stacks[cid % len(stacks)]
        self.sys_prompt = DISTILL_SYSTEM_PROMPTS[cid % len(DISTILL_SYSTEM_PROMPTS)]
        self.sys_hash = sha(self.sys_prompt, 16)
        payments = [sha(f"pm-batch-{cid}-{i}", 16) for i in range(3)]
        subnets = [f"{rng.choice([13, 34, 35, 52])}.{rng.randint(64, 250)}.{rng.randint(0, 255)}"
                   for _ in range(3)]
        self.accounts = []
        for i in range(n_accounts):
            asn = rng.choice(ASN_CLOUD)
            self.accounts.append({
                "account_id": "sk-" + sha(f"distill-{cid}-{i}"),
                "ip": f"{subnets[i % 3]}.{rng.randint(1, 254)}",
                "asn": asn,
                "country": rng.choice(["CN", "US", asn[2]]),
                "payment": payments[i % 3],
                # most accounts hide behind a spoofed browser UA (the
                # UA/TLS mismatch the fingerprint worker exists to catch);
                # a couple don't bother
                "ua": rng.choice(UA_BROWSER) if i % 4 != 3 else UA_SCRIPT[self.ja3_label],
                "seq": 0,
            })

    def burst(self, ts):
        """One synchronized round: every account sends 2 requests within ~2s."""
        events = []
        rng = self.rng
        for acct in self.accounts:
            for k in range(2):
                jitter = timedelta(milliseconds=rng.randint(0, 1800))
                t = ts + jitter
                topic = DISTILL_TOPICS[(acct["seq"] // 3) % len(DISTILL_TOPICS)]
                prompt = rng.choice(DISTILL_PROMPTS[topic])
                ev = base_event(rng, t, acct["account_id"], acct["ip"],
                                acct["asn"], acct["country"])
                ev.update({
                    "user_agent": acct["ua"],
                    "model": MODEL_SWEEP[(acct["seq"] // 6) % len(MODEL_SWEEP)],
                    "prompt": prompt,
                    "token_count": rng.randint(12, 22),  # uniform template lengths
                    "payment_method_hash": acct["payment"],
                    "header_order": HEADER_ORDER_PYTHON,
                    "ja3_hash": JA3_SCRIPT[self.ja3_label],
                    "ja3s_hash": rng.choice(JA3S_SCRIPT_ONLY),
                    "h2_settings": h2_block(self.h2_label, mcs=100),
                    "tls_library": "OpenSsl" if self.ja3_label.startswith("python") else "GoTls",
                    "max_tokens": MAX_TOKENS_SWEEP[acct["seq"] % len(MAX_TOKENS_SWEEP)],
                    "system_prompt_hash": self.sys_hash,
                    "campaign_label": self.label,
                })
                acct["seq"] += 1
                events.append(ev)
        return events


# ── Batch generation (deterministic) ─────────────────────────────────────────

def generate_batch(count, seed, n_campaigns):
    rng = random.Random(seed)
    benign = [BenignAccount(rng, i) for i in range(150)]
    campaigns = [Campaign(rng, i + 1) for i in range(n_campaigns)]

    events = []
    # Simulate enough rounds to cover `count` after truncation.
    # Benign: Poisson-ish arrivals, ~2 events/sec across the population.
    # Campaigns: synchronized burst every 90 simulated seconds.
    t = 0.0
    burst_at = {c.cid: 15.0 + 5.0 * c.cid for c in campaigns}
    while len(events) < count * 1.3:
        t += rng.expovariate(2.0)
        ts = SIM_EPOCH + timedelta(seconds=t)
        acct = rng.choice(benign)
        events.append(acct.event(ts))
        for c in campaigns:
            if t >= burst_at[c.cid]:
                events.extend(c.burst(SIM_EPOCH + timedelta(seconds=burst_at[c.cid])))
                burst_at[c.cid] += 90.0

    events.sort(key=lambda e: e["timestamp"])
    return events[:count]


# ── Streaming mode (wall clock, infinite) ─────────────────────────────────────

def stream(rate, seed, n_campaigns, out):
    rng = random.Random(seed)
    benign = [BenignAccount(rng, i) for i in range(150)]
    campaigns = [Campaign(rng, i + 1) for i in range(n_campaigns)]
    next_burst = time.monotonic() + 10.0
    while True:
        now = datetime.now(timezone.utc)
        if time.monotonic() >= next_burst:
            for c in campaigns:
                for ev in c.burst(now):
                    out.write(json.dumps(ev) + "\n")
            next_burst += 90.0
        else:
            out.write(json.dumps(rng.choice(benign).event(now)) + "\n")
        out.flush()
        time.sleep(1.0 / max(0.1, rate))


def main():
    p = argparse.ArgumentParser(description="Glasswally synthetic log generator")
    p.add_argument("--output", default="-", help="Output file (default: stdout)")
    p.add_argument("--rate", type=float, default=5, help="Events/sec in streaming mode")
    p.add_argument("--count", type=int, default=0, help="Total events (0 = infinite stream)")
    p.add_argument("--seed", type=int, default=42, help="RNG seed for reproducibility")
    p.add_argument("--campaigns", type=int, default=3, help="Number of distillation campaigns")
    args = p.parse_args()

    out = open(args.output, "w") if args.output != "-" else sys.stdout
    try:
        if args.count > 0:
            events = generate_batch(args.count, args.seed, args.campaigns)
            for ev in events:
                out.write(json.dumps(ev) + "\n")
            pos = sum(1 for ev in events if ev["campaign_label"])
            print(f"Generated {len(events)} events ({pos} positive) → {args.output}",
                  file=sys.stderr)
        else:
            stream(args.rate, args.seed, args.campaigns, out)
    finally:
        if out is not sys.stdout:
            out.close()


if __name__ == "__main__":
    main()
