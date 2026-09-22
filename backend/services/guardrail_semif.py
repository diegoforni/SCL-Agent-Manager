"""Inline SemIf guardrail — local open-source Jev-pattern decisions (CLI).

Fourth guardrail type, alongside the in-container opencode judge (per-command
verdicts), the offline embeddings classifiers, and the Jev System One service
(guardrail_jev). Same orchestration-level contract as Jev: callers POST an
unstructured payload — a user prompt or an autonomous agent's reasoning
trace — and get back a typed probabilistic decision plus a routed action:
block / review (human) / allow.

SemIf (https://github.com/TheoLeeCJ/SemIf, formerly OpenJev) reimplements the
*interface pattern* behind Jev with open models, locally: one forward pass
reads the declared option logits directly — no sampled answer token, no JSON
repair. This module keeps the Jev decision contract (is_malicious noul +
threat_category choice, imported from guardrail_jev so the criteria text is
byte-identical and the two scorers are A/B comparable) but swaps the
transport: instead of POSTing OpenRouter it execs the `semif-score` CLI on a
two-row JSONL (one row per question) and reads the option probabilities:

  is_malicious (noul)      → row with options [true, false]; noul = P("true")
  threat_category (choice) → row with one option per criteria key; choice /
                             probabilities = argmax / full distribution

LOCAL, NOT HOSTED: no API key; the model runs wherever this backend runs.
The CLI loads the model once per invocation, so per-call latency includes
model load (seconds with the 4B Q4_K_M GGUF on CPU) — fine for shadow/
benchmark use; the benchmark harness scores in one batched CLI run instead.
Default backend is llama.cpp over a local GGUF (CPU box); SEMIF_BACKEND=torch
switches to the HF weights path (GPU boxes hold the 4B in BF16).

Fail-safe is ESCALATE, never silent allow: an unavailable scorer, missing
GGUF, or unparseable output routes to human review (same policy as the Jev
service and the TS judge's judge_fail=escalate default). Telemetry appends to
OUTPUTS_DIR/semif/evaluations.ndjson for later benchmarking.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .guardrail_jev import (
    QUESTIONS,
    JevDecision,
    JevGuardrailError,
    route_decision,
)

logger = logging.getLogger("agent_manager.guardrail_semif")

# ── Configuration ─────────────────────────────────────────────────────

# Manifests-pinned defaults (SemIf manifests/models.json): SemIf's primary
# direct-option-logits model Qwen3.5-4B (reference tokenizer revision) with
# its bartowski Q4_K_M GGUF (~3.0 GB) for the CPU llama.cpp path. The 0.6B
# ladder model (rev c1899de2…, Q8_0 GGUF 639 MB) is a fine slower-box
# fallback — just override SEMIF_MODEL/SEMIF_REVISION/SEMIF_GGUF.
DEFAULT_SCORE_CMD = "semif-score"
DEFAULT_BACKEND = "llamacpp"
DEFAULT_MODEL = "Qwen/Qwen3.5-4B"
DEFAULT_REVISION = "851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a"
DEFAULT_GGUF = ""
DEFAULT_BLOCK_THRESHOLD = 0.90
DEFAULT_REVIEW_THRESHOLD = 0.60
DEFAULT_TIMEOUT_S = 300.0  # CLI model load + CPU forward of a 4B, not an API RTT
DEFAULT_MAX_TOKENS = 4096

MAL_ROW_ID = "is_malicious"
CAT_ROW_ID = "threat_category"


class SemIfGuardrailError(JevGuardrailError):
    """SemIf scorer unavailable / unparseable / unconfigured.

    Same contract as JevGuardrailError (reason + status_code the router
    answers with); separate class so callers can tell the two guardrails
    apart in telemetry."""


# ── Config resolution ─────────────────────────────────────────────────


def _env_str(name: str, default: str) -> str:
    val = os.getenv(name)
    return val if val and val.strip() else default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw.strip())
    except ValueError:
        logger.warning("SEMIF config %s=%r not a float — using default %s", name, raw, default)
        return default


def _resolve_gguf() -> Path | None:
    raw = _env_str("SEMIF_GGUF", DEFAULT_GGUF)
    return Path(raw) if raw else None


def get_effective_config() -> dict[str, Any]:
    """Effective SemIf guardrail configuration for GET /config (no secrets —
    there are none: everything is local paths and pinned revisions)."""
    gguf = _resolve_gguf()
    return {
        "score_cmd": _env_str("SEMIF_SCORE_CMD", DEFAULT_SCORE_CMD),
        "backend": _env_str("SEMIF_BACKEND", DEFAULT_BACKEND),
        "model": _env_str("SEMIF_MODEL", DEFAULT_MODEL),
        "revision": _env_str("SEMIF_REVISION", DEFAULT_REVISION),
        "gguf": str(gguf) if gguf else "",
        "gguf_present": bool(gguf and gguf.is_file()),
        "llama_threads": int(_env_float("SEMIF_LLAMA_THREADS", 0)) or None,
        "max_tokens": max(1, int(_env_float("SEMIF_MAX_TOKENS", DEFAULT_MAX_TOKENS))),
        "block_threshold": _env_float("SEMIF_BLOCK_THRESHOLD", DEFAULT_BLOCK_THRESHOLD),
        "review_threshold": _env_float("SEMIF_REVIEW_THRESHOLD", DEFAULT_REVIEW_THRESHOLD),
        "timeout_s": _env_float("SEMIF_TIMEOUT_S", DEFAULT_TIMEOUT_S),
        "eval_log_enabled": _env_str("SEMIF_EVAL_LOG_ENABLED", "true").lower() != "false",
    }


def _check_configured(cfg: dict[str, Any]) -> None:
    """Fail fast with a clear 503 when the scorer cannot run at all."""
    if not shutil.which(shlex.split(cfg["score_cmd"])[0]) and not Path(
            shlex.split(cfg["score_cmd"])[0]).is_file():
        raise SemIfGuardrailError(
            f"semif-score CLI not found ({cfg['score_cmd']!r} — install SemIf "
            "and point SEMIF_SCORE_CMD at its venv entrypoint)", status_code=503)
    if cfg["backend"] == "llamacpp" and not cfg["gguf_present"]:
        raise SemIfGuardrailError(
            "SEMIF_GGUF not configured or file missing (llama.cpp backend "
            "needs a local GGUF checkpoint)", status_code=503)


# ── Request construction (Jev questions → SemIf JSONL rows) ──────────


def _build_rows(payload_text: str,
                questions: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """Two decision rows sharing the payload as state — SemIf's equivalent
    of the Jev questions object. The payload IS the state; the option
    descriptions carry the same criteria text Jev scores against."""
    q = questions if questions is not None else QUESTIONS
    mal, cat = q["is_malicious"], q["threat_category"]
    return [
        {
            "id": MAL_ROW_ID,
            "state": payload_text,
            "question": mal["instructions"],
            "options": [
                {"id": "true", "description": mal["criteria"]["true"]},
                {"id": "false", "description": mal["criteria"]["false"]},
            ],
        },
        {
            "id": CAT_ROW_ID,
            "state": payload_text,
            "question": cat["instructions"],
            "options": [{"id": key, "description": desc}
                        for key, desc in cat["criteria"].items()],
        },
    ]


def _validate_question_override(questions: Any) -> dict[str, Any]:
    """Same shape check as the Jev service: both contract keys present with
    the right discriminator types (a noul question needs true/false criteria,
    a choice question needs ≥2 criteria to map onto options)."""
    if not isinstance(questions, dict):
        raise SemIfGuardrailError("questions override must be an object", status_code=400)
    mal, cat = questions.get("is_malicious"), questions.get("threat_category")
    if not isinstance(mal, dict) or mal.get("type") != "noul":
        raise SemIfGuardrailError("questions.is_malicious must be a noul question", status_code=400)
    if not isinstance(cat, dict) or cat.get("type") != "choice":
        raise SemIfGuardrailError("questions.threat_category must be a choice question", status_code=400)
    if not isinstance(mal.get("criteria"), dict) or set(mal["criteria"]) != {"true", "false"}:
        raise SemIfGuardrailError(
            "questions.is_malicious criteria must have exactly true/false keys "
            "(they become the two options)", status_code=400)
    if not isinstance(cat.get("criteria"), dict) or not 2 <= len(cat["criteria"]) <= 16:
        raise SemIfGuardrailError(
            "questions.threat_category needs 2-16 criteria (they become the "
            "options; SemIf caps options at 16)", status_code=400)
    return questions


# ── CLI seam (monkeypatched in tests) ─────────────────────────────────


def _score_command(cfg: dict[str, Any]) -> list[str]:
    cmd = shlex.split(cfg["score_cmd"])
    cmd += [
        "--mode", "direct",
        "--backend", cfg["backend"],
        "--model", cfg["model"],
        "--revision", cfg["revision"],
        "--max-tokens", str(cfg["max_tokens"]),
        "--input", "__INPUT__",   # replaced by the caller with temp paths
        "--output", "__OUTPUT__",
    ]
    if cfg["backend"] == "llamacpp":
        cmd += ["--gguf", str(cfg["gguf"])]
        if cfg["llama_threads"]:
            cmd += ["--llama-threads", str(cfg["llama_threads"])]
    return cmd


async def _run_semif_score(rows: list[dict[str, Any]], cfg: dict[str, Any],
                           *, timeout_s: float) -> list[dict[str, Any]]:
    """Write rows to a fresh temp JSONL, exec semif-score, parse the output.

    The CLI is create-only (refuses an existing --output) and loads the
    model per invocation — a unique temp dir per call satisfies both.
    Raises SemIfGuardrailError on non-zero exit, timeout, or bad output."""
    with tempfile.TemporaryDirectory(prefix="semif-guardrail-") as td:
        in_path = Path(td) / "input.jsonl"
        out_path = Path(td) / "output.jsonl"
        in_path.write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
            encoding="utf-8")
        cmd = [str(in_path) if a == "__INPUT__" else
               str(out_path) if a == "__OUTPUT__" else a
               for a in _score_command(cfg)]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError as exc:
            raise SemIfGuardrailError(f"could not exec {cmd[0]!r}: {exc}", status_code=503) from exc
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.communicate()
            raise SemIfGuardrailError(
                f"semif-score timed out after {timeout_s:.0f}s (model load + "
                "forward on CPU — raise SEMIF_TIMEOUT_S or use a smaller GGUF)",
                status_code=504) from exc
        if proc.returncode != 0:
            tail = (stderr or b"").decode(errors="replace")[-400:]
            raise SemIfGuardrailError(
                f"semif-score exited {proc.returncode}: {tail}", status_code=502)
        try:
            results = [json.loads(line) for line in
                       out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, ValueError) as exc:
            raise SemIfGuardrailError(f"semif-score output unparseable: {exc}", status_code=502) from exc
        if len(results) != len(rows):
            raise SemIfGuardrailError(
                f"semif-score returned {len(results)} rows for {len(rows)} inputs",
                status_code=502)
        return results


# ── Telemetry ─────────────────────────────────────────────────────────


def _append_eval_log(record: dict[str, Any]) -> None:
    """Best-effort one-line JSONL append for later benchmarking — never raises."""
    try:
        if _env_str("SEMIF_EVAL_LOG_ENABLED", "true").lower() == "false":
            return
        out_dir = Path(os.getenv("OUTPUTS_DIR", "/outputs")) / "semif"
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "evaluations.ndjson").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as exc:
        logger.warning("SemIf eval-log append failed (ignored): %s", exc)


# ── Output parsing ────────────────────────────────────────────────────


def _parse_results(results: list[dict[str, Any]]) -> tuple[JevDecision, dict[str, Any]]:
    """SemIf output rows → spec-shaped JevDecision + raw answer fields.

    noul = probability of the "true" option on the is_malicious row (a
    binary softmax — the direct-logit equivalent of Jev's noul).
    threat_category = argmax option on the category row; its distribution
    lands in raw.category_probabilities. The category is REPORT-ONLY (an
    override's criteria define its own enum), so any option id passes."""
    by_id = {r.get("id"): r for r in results}
    mal, cat = by_id.get(MAL_ROW_ID), by_id.get(CAT_ROW_ID)
    if not mal or not cat:
        raise SemIfGuardrailError(
            f"SemIf did not answer both questions: {[r.get('id') for r in results]}")
    try:
        mal_p = float(mal["probabilities"][mal["option_ids"].index("true")])
        cat_probs = {str(k): float(v) for k, v in zip(cat["option_ids"], cat["probabilities"])}
    except (KeyError, ValueError, IndexError) as exc:
        raise SemIfGuardrailError(f"SemIf row shape unexpected: {exc}", status_code=502) from exc
    if not 0.0 <= mal_p <= 1.0:
        raise SemIfGuardrailError(f"SemIf returned out-of-range probability {mal_p}")
    category = max(cat_probs, key=cat_probs.get)  # argmax; ties → first listed
    is_malicious = mal_p >= 0.5
    decision = JevDecision(
        is_malicious=is_malicious,
        confidence_score=mal_p if is_malicious else 1.0 - mal_p,
        threat_category=category,  # type: ignore[arg-type]
    )
    raw = {
        "malicious_probability": mal_p,
        "category_choice": category,
        "category_confidence": cat_probs[category],
        "category_probabilities": cat_probs,
        "answers": {
            "is_malicious": {"type": "noul", "noul": mal_p},
            "threat_category": {"type": "choice", "choice": category,
                                "confidence": cat_probs[category],
                                "probabilities": cat_probs},
        },
        "option_logits": {
            MAL_ROW_ID: mal.get("option_logits"),
            CAT_ROW_ID: cat.get("option_logits"),
        },
    }
    return decision, raw


# ── Entry point ───────────────────────────────────────────────────────


async def evaluate_payload(
    payload_text: str,
    *,
    source: Optional[str] = None,
    run_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    questions: Optional[dict[str, Any]] = None,
    variant: Optional[str] = None,
) -> dict[str, Any]:
    """Classify one payload via local SemIf and return the routed decision.

    Same signature/contract as guardrail_jev.evaluate_payload: `questions`
    (validated by _validate_question_override) replaces the deployed
    question set for benchmark/prompt iteration; `variant` tags telemetry.
    Raises SemIfGuardrailError (503 unconfigured / 502 subprocess or parse
    failure / 504 timeout / 400 bad override); the router converts those
    into fail-safe review/escalate responses."""
    if questions is not None:
        _validate_question_override(questions)

    cfg = get_effective_config()
    _check_configured(cfg)
    rows = _build_rows(payload_text, questions)

    started = time.monotonic()
    usage: dict[str, Any] = {}
    raw: dict[str, Any] = {}
    try:
        results = await _run_semif_score(rows, cfg, timeout_s=cfg["timeout_s"])
        decision, raw = _parse_results(results)
        input_tokens = sum(int(r.get("input_tokens") or 0) for r in results)
        usage = {"input_tokens": input_tokens, "output_tokens": 0,
                 "total_tokens": input_tokens, "cost": 0.0}  # local: free
        action, platform_decision, reason = route_decision(
            decision,
            block_threshold=cfg["block_threshold"],
            review_threshold=cfg["review_threshold"])
        error = None
    except JevGuardrailError as exc:
        decision, action, platform_decision, reason, error = (
            None, "review", "escalate", f"fail-safe: {exc.reason}", exc.reason)
        raise
    finally:
        latency_ms = int((time.monotonic() - started) * 1000)
        _append_eval_log({
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": source, "run_id": run_id, "agent_id": agent_id,
            "variant": variant,
            "decision": decision.model_dump() if decision else None,
            "raw": raw or None,
            "action": action, "platform_decision": platform_decision,
            "reason": reason, "error": error,
            "model": cfg["model"], "backend": cfg["backend"],
            "latency_ms": latency_ms,
            "payload_chars": len(payload_text),
            "usage_tokens": usage.get("total_tokens"),
            "cost_usd": 0.0,
        })

    return {
        "decision": decision.model_dump(),
        "semif": raw,
        "action": action,
        "platform_decision": platform_decision,
        "reason": reason,
        "model": cfg["model"],
        "backend": cfg["backend"],
        "latency_ms": latency_ms,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "usage": {
            "prompt_tokens": usage.get("input_tokens"),
            "completion_tokens": 0,  # direct logit readout: nothing sampled
            "total_tokens": usage.get("total_tokens"),
            "cost": 0.0,  # local inference — no metered cost
        },
    }
