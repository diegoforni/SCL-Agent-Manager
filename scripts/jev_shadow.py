#!/usr/bin/env python3
"""Jev shadow tailer — mirror a live coder56 run through the inline Jev guardrail.

Tails /outputs/<run_id>/guardrail/verdicts.ndjson (every command the in-container
opencode judge adjudicated) and classifies each COMMAND through
POST /api/guardrail/jev/evaluate (Jev System One via OpenRouter Decisions),
writing one comparison line per command to /outputs/<run_id>/jev_shadow.ndjson
plus running Jev-vs-judge agreement + cost stats to stdout.

OBSERVATION ONLY: never blocks, delays, or modifies the run — the third
guardrail runs in shadow so the next experiment gets a measured baseline
(Jev decision vs judge decision per command, per-call cost/latency).

Payload policy: COMMAND-ONLY (matches the embedding-winner baseline
knn5_wvote_cmdonly; goal/scope-context ablation belongs to the next
experiment, not this harness).

Usage:
    python3 scripts/jev_shadow.py <run_id> [--api http://127.0.0.1:9005]
    OUTPUTS_DIR=/home/diego/SCLT/stratocyberlab/outputs (default below)
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_OUTPUTS = "/home/diego/SCLT/stratocyberlab/outputs"
POLL_S = 2.0
MAX_RETRIES = 3

# Judge verdict vocabulary → Jev action bucket (sanitize counts as its own
# bucket: a partial allow the binary Jev action can't represent).
JUDGE_BUCKET = {
    "execute": "allow",
    "refuse": "block",
    "escalate": "review",
    "sanitize": "sanitize",
}


def post_evaluate(api: str, command: str, run_id: str) -> dict:
    body = json.dumps({
        "payload_text": command,
        "source": "command-shadow",
        "run_id": run_id,
    }).encode()
    req = urllib.request.Request(
        api, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode())


def classify(api: str, command: str, run_id: str) -> dict:
    """Evaluate with retries; fail-soft (a dead shadow never stalls evidence)."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return post_evaluate(api, command, run_id)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as exc:
            if attempt == MAX_RETRIES:
                return {"error": f"{type(exc).__name__}: {exc}"}
            time.sleep(2.0 * attempt)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--api", default="http://127.0.0.1:9005/api/guardrail/jev/evaluate")
    args = ap.parse_args()

    outputs = Path(os.environ.get("OUTPUTS_DIR", DEFAULT_OUTPUTS))
    verdicts_path = outputs / args.run_id / "guardrail" / "verdicts.ndjson"
    shadow_path = outputs / args.run_id / "jev_shadow.ndjson"

    print(f"[jev-shadow] run={args.run_id} verdicts={verdicts_path} api={args.api}", flush=True)
    offset = 0
    seq = 0
    stats = {"evaluated": 0, "errors": 0, "cost_usd": 0.0,
             "agree": 0, "disagree": 0, "by_action": {}}

    while True:
        if not verdicts_path.exists():
            time.sleep(POLL_S)
            continue
        size = verdicts_path.stat().st_size
        if size < offset:  # truncated/rotated — restart from beginning
            offset = 0
        if size == offset:
            time.sleep(POLL_S)
            continue

        with verdicts_path.open("rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
            offset = fh.tell()

        for raw in chunk.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                v = json.loads(raw)
            except ValueError:
                continue  # malformed line: salvage parser's job, not ours
            command = v.get("command")
            judge_decision = v.get("decision")
            if not command or not judge_decision:
                continue

            seq += 1
            res = classify(args.api, command, args.run_id)
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "seq": seq,
                "judge_decision": judge_decision,
                "judge_bucket": JUDGE_BUCKET.get(judge_decision, "other"),
                "command": command,
            }
            if "error" in res:
                stats["errors"] += 1
                rec["error"] = res["error"]
            else:
                decision = res.get("decision") or {}
                action = res.get("action")
                stats["evaluated"] += 1
                stats["cost_usd"] += res.get("usage", {}).get("cost") or 0.0
                rec.update({
                    "jev_action": action,
                    "jev_platform_decision": res.get("platform_decision"),
                    "jev_is_malicious": decision.get("is_malicious"),
                    "jev_confidence": decision.get("confidence_score"),
                    "jev_threat_category": decision.get("threat_category"),
                    "jev_malicious_probability": (res.get("jev") or {}).get("malicious_probability"),
                    "jev_category_probabilities": (res.get("jev") or {}).get("category_probabilities"),
                    "latency_ms": res.get("latency_ms"),
                    "cost_usd": res.get("usage", {}).get("cost"),
                })
                bucket = rec["judge_bucket"]
                if bucket in ("allow", "block", "review"):
                    if action == bucket:
                        stats["agree"] += 1
                    else:
                        stats["disagree"] += 1
                stats["by_action"][action] = stats["by_action"].get(action, 0) + 1

            with shadow_path.open("a", encoding="utf-8") as out:
                out.write(json.dumps(rec, ensure_ascii=False) + "\n")

            if seq % 10 == 0 or "error" in res:
                print(f"[jev-shadow] seq={seq} evaluated={stats['evaluated']} "
                      f"errors={stats['errors']} agree={stats['agree']} "
                      f"disagree={stats['disagree']} cost=${stats['cost_usd']:.6f}",
                      flush=True)

        print(f"[jev-shadow] seq={seq} evaluated={stats['evaluated']} "
              f"agree={stats['agree']} disagree={stats['disagree']} "
              f"cost=${stats['cost_usd']:.6f} — waiting for more verdicts",
              flush=True)


if __name__ == "__main__":
    sys.exit(main())
