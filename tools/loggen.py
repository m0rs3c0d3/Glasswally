#!/usr/bin/env python3
"""
Glasswally synthetic API gateway log generator.

Generates realistic LLM API request events in JSONL format.  Two traffic
classes are interleaved:

  - benign    — legitimate user traffic (null campaign_label)
  - distill   — simulated distillation campaign (campaign_label set)

Output format is one JSON object per line, compatible with:
  - glasswally --mode tail
  - glasswally --mode eval (labeled dataset evaluation)

Usage:
  python tools/loggen.py --output /tmp/access.jsonl --rate 5 --seed 42
  python tools/loggen.py --output labeled_dataset.jsonl --count 5000 --labeled
"""

import argparse
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timezone


# ── Benign traffic templates ──────────────────────────────────────────────────

BENIGN_PROMPTS = [
    "Explain the difference between TCP and UDP in simple terms.",
    "Write a Python function to parse CSV files.",
    "Summarize the plot of Pride and Prejudice in three sentences.",
    "What are the main causes of the French Revolution?",
    "How do I center a div in CSS?",
    "Translate 'hello world' into Spanish, French, and German.",
    "Review my cover letter and suggest improvements: {placeholder}",
    "What is the time complexity of quicksort?",
    "Help me debug this JavaScript: console.log(typeof null)",
    "Write a haiku about autumn.",
    "What foods are high in vitamin C?",
    "Explain photosynthesis to a 10-year-old.",
    "What are best practices for REST API design?",
    "How does HTTPS work?",
    "Compare React and Vue for frontend development.",
]

BENIGN_MODELS = ["gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet", "claude-3-haiku"]
BENIGN_TOKENS = [256, 512, 1024, 2048]
BENIGN_ASNS   = [
    ("7922",  "Comcast Cable"),
    ("3320",  "Deutsche Telekom"),
    ("4134",  "CHINANET"),
    ("1221",  "Telstra"),
    ("5089",  "Virgin Media"),
]


# ── Distillation campaign templates ───────────────────────────────────────────

DISTILL_SYSTEM_PROMPTS = [
    "You are a helpful AI that answers technical questions accurately and comprehensively.",
    "You are an expert assistant. Answer every question as if training a student model.",
    "Respond as a knowledgeable AI. Your answers will be used for research purposes.",
    "You are GPT-4. Provide detailed, expert-level responses to all queries.",
    "Act as an AI teacher. Explain concepts clearly for a machine learning dataset.",
]

DISTILL_COT_PROMPTS = [
    "Think step by step: what is the capital of France?",
    "Let's work through this carefully: explain gradient descent.",
    "Reason through this: how does a hash table work?",
    "Step by step reasoning: why is the sky blue?",
    "Chain of thought: what are the steps to reverse a linked list?",
    "Walk me through your thinking: how does RSA encryption work?",
    "Explain your reasoning: what causes inflation?",
    "Think out loud: how does a compiler work?",
]

DISTILL_MODELS_SWEEP = [
    "gpt-4o", "gpt-4", "gpt-3.5-turbo",
    "claude-3-5-sonnet", "claude-3-opus", "claude-3-haiku",
    "gpt-4o-mini",
]

DISTILL_ASNS = [
    ("16509", "Amazon AWS"),
    ("15169", "Google Cloud"),
    ("8075",  "Microsoft Azure"),
    ("24940", "Hetzner"),
    ("20473", "Vultr"),
    ("14061", "DigitalOcean"),
]

MAX_TOKENS_SWEEP = [4096, 8192, 16384, 32768, 65536, 131072]


# ── Event generation ───────────────────────────────────────────────────────────

def make_account_id(seed_str: str) -> str:
    return "sk-" + hashlib.sha256(seed_str.encode()).hexdigest()[:24]


def make_ip(rng: random.Random, asn_pool: list) -> tuple[str, str, str]:
    asn_num, asn_org = rng.choice(asn_pool)
    return (
        f"{rng.randint(1,254)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        asn_num,
        asn_org,
    )


def benign_event(rng: random.Random, ts: datetime) -> dict:
    account_id = make_account_id(f"benign-{rng.randint(0, 200)}")
    ip, asn_num, asn_org = make_ip(rng, BENIGN_ASNS)
    return {
        "account_id":         account_id,
        "timestamp":          ts.isoformat(),
        "model":              rng.choice(BENIGN_MODELS),
        "prompt":             rng.choice(BENIGN_PROMPTS),
        "system_prompt":      None,
        "system_prompt_hash": None,
        "token_count":        rng.randint(10, 200),
        "max_tokens":         rng.choice(BENIGN_TOKENS),
        "client_ip":          ip,
        "asn_number":         int(asn_num),
        "asn_org":            asn_org,
        "user_agent":         "python-requests/2.31.0",
        "h2_settings_fp":     None,
        "campaign_label":     None,
    }


def distill_event(rng: random.Random, ts: datetime, campaign_id: str, seq: int) -> dict:
    account_id  = make_account_id(f"distill-{campaign_id}-{rng.randint(0, 5)}")
    ip, asn_num, asn_org = make_ip(rng, DISTILL_ASNS)
    sys_prompt   = rng.choice(DISTILL_SYSTEM_PROMPTS)
    sys_hash     = hashlib.sha256(sys_prompt.encode()).hexdigest()[:16]
    # Rotate models to sweep capabilities
    model        = DISTILL_MODELS_SWEEP[seq % len(DISTILL_MODELS_SWEEP)]
    # Use CoT prompt
    prompt       = rng.choice(DISTILL_COT_PROMPTS)
    # High max_tokens (greedy budget probing)
    max_tokens   = MAX_TOKENS_SWEEP[seq % len(MAX_TOKENS_SWEEP)]
    return {
        "account_id":         account_id,
        "timestamp":          ts.isoformat(),
        "model":              model,
        "prompt":             prompt,
        "system_prompt":      sys_prompt,
        "system_prompt_hash": sys_hash,
        "token_count":        rng.randint(8, 30),
        "max_tokens":         max_tokens,
        "client_ip":          ip,
        "asn_number":         int(asn_num),
        "asn_org":            asn_org,
        "user_agent":         "aiohttp/3.9.1",
        "h2_settings_fp":     f"2:{rng.randint(0,65535)}:3:100:4:65535:5:16384",
        "campaign_label":     f"campaign_{campaign_id}",
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def generate(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    campaign_ids = [f"{i:04d}" for i in range(1, args.campaigns + 1)]

    out = open(args.output, "w") if args.output != "-" else sys.stdout
    count = 0
    distill_seq: dict[str, int] = {c: 0 for c in campaign_ids}

    try:
        while args.count == 0 or count < args.count:
            now = datetime.now(timezone.utc)

            # 20% distillation traffic, 80% benign
            if rng.random() < 0.20:
                campaign = rng.choice(campaign_ids)
                event = distill_event(rng, now, campaign, distill_seq[campaign])
                distill_seq[campaign] += 1
            else:
                event = benign_event(rng, now)

            out.write(json.dumps(event) + "\n")
            out.flush()
            count += 1

            if args.count == 0:
                time.sleep(1.0 / max(1, args.rate))

    finally:
        if out is not sys.stdout:
            out.close()

    if args.count > 0:
        pos = sum(1 for _ in open(args.output) if json.loads(_)["campaign_label"]) if args.output != "-" else "?"
        print(f"Generated {count} events ({pos} positive) → {args.output}", file=sys.stderr)


def main() -> None:
    p = argparse.ArgumentParser(description="Glasswally synthetic log generator")
    p.add_argument("--output",    default="-",           help="Output file (default: stdout)")
    p.add_argument("--rate",      type=float, default=5, help="Events/sec in streaming mode")
    p.add_argument("--count",     type=int,   default=0, help="Total events (0 = infinite)")
    p.add_argument("--seed",      type=int,   default=42,help="RNG seed for reproducibility")
    p.add_argument("--campaigns", type=int,   default=3, help="Number of distillation campaigns")
    args = p.parse_args()
    generate(args)


if __name__ == "__main__":
    main()
