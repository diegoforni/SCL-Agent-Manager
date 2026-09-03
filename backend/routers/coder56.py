"""
Coder56 Pentest Console router.

Operator-driven surface for running scoped red-team engagements with the coder56
agent under a human-in-the-loop (HITL) guardrail. This router is consumed by the
standalone Coder56 console frontend (coder56-console/).

Four criticality levels (see models.Criticality) drive guardrail behavior via
/outputs/<run_id>/guardrail/mode.txt, read per-command by guardrail.ts:
  low    -> pass-through (no approvals)
  medium -> pause when the guardrail flags a command (refuse/sanitize/escalate)
  high   -> pause EVERY command for explicit operator approval
  auto   -> active guardrail, fully autonomous: judge every command, apply the
            verdict with NO human (execute/sanitize run; refuse returns feedback)

Approvals are exchanged over the shared /outputs filesystem (the same channel
guardrail.ts already uses for goal.txt), so this router needs no direct
in-process link to the topology containers:
  guardrail writes  /outputs/<run_id>/guardrail/approvals/<id>.req.json
  operator writes   /outputs/<run_id>/guardrail/approvals/<id>.dec.json   (here)

Endpoints:
  POST   /api/coder56/launch                 orchestrate a run
  GET    /api/coder56/runs/{run_id}/approvals pending + recently-decided queue
  POST   /api/coder56/approvals/{id}/decide   operator decision
  GET    /api/coder56/runs/{run_id}/verdicts  tail guardrail verdicts.ndjson
  GET    /api/coder56/runs/{run_id}/messages  agent message stream (session)
  POST   /api/coder56/runs/{run_id}/guide     free-form operator follow-up
  POST   /api/coder56/goal/draft              LLM-authored engagement draft
  POST   /api/coder56/goal/compile            deterministic directive compile
  GET    /api/coder56/mitre/catalog           ATT&CK tactic/technique catalog
  GET    /api/coder56/runs                    recent run ids under /outputs
"""
from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from ..models import (
    AgentType,
    AddRunRequest,
    AdvanceRequest,
    ApprovalDecision,
    ApprovalReq,
    Criticality,
    DecideRequest,
    Engagement,
    EngagementCreate,
    EngagementMode,
    EngagementStatus,
    EngagementUpdate,
    Finding,
    FindingCreate,
    FindingStatus,
    FindingUpdate,
    FindingsDraftRequest,
    GoalCompileRequest,
    GoalDirective,
    GoalDraftRequest,
    GuideRequest,
    JudgeFailRequest,
    LaunchRequest,
    LaunchResponse,
    MitrePhaseSelection,
    Orchestration,
    OwaspPlanRequest,
    PhaseMode,
    PhaseModeRequest,
    PhaseRuntime,
    PhaseSpec,
    PhaseStatus,
    PlannedPhaseDraftRequest,
    PlannedRun,
    PlannedRunStatus,
    PlannedRunUpdate,
    SandboxStatus,
    Severity,
    SessionCreateRequest,
)
from ..services.session_capture import OUTPUTS_DIR, resolve_run_id
from ..services.mitre_catalog import catalog as mitre_catalog
from ..services.owasp_catalog import catalog as owasp_catalog
from ..services.api_security_catalog import catalog as api_security_catalog
from ..services.report_renderer import render_report, render_client_report
from ..services.docker_client import create_docker_client
from ..services.engagement_metrics import build_engagement_metrics
from .topologies import fetch_from_topology_plugin, post_to_topology_plugin

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/coder56", tags=["coder56"])

POLL_JOB_INTERVAL_S = 2.0
POLL_JOB_TIMEOUT_S = 300.0
_engagement_locks: Dict[str, asyncio.Lock] = {}


def _engagement_lock(engagement_id: str) -> asyncio.Lock:
    """Serialize read-modify-write cycles for one engagement ledger."""
    lock = _engagement_locks.get(engagement_id)
    if lock is None:
        lock = asyncio.Lock()
        _engagement_locks[engagement_id] = lock
    return lock

# ---------------------------------------------------------------------------
# Container-busy guard (one-run-per-host hard launch gate)
#
# Two launches against the same (topology_id, host_id) MUST NOT coexist: the
# lead-driver writes the shared per-host guardrail state (mode.txt/goal.txt) and
# drives ONE coder56_lead session, so a second launch would silently clobber the
# first run's manifest and verdicts.  The guard is enforced as a HARD launch gate
# (HTTP 409 before any topology bring-up) using two independent signals:
#   1. an in-process registry of active lead-driver tasks per host (instant,
#      authoritative for live runs); AND
#   2. a restart-surviving scan of recent guardrail verdicts for that host
#      (the registry is wiped on a dashboard restart, so a run that is still
#      live in the container must still be detected).
# Either signal busy => refuse.  The registry is released when _lead_driver exits
# (see _release_host_run) so a host frees up as soon as its run finishes.
# ---------------------------------------------------------------------------
BUSY_RECENT_VERDICT_S = float(os.getenv("CODER56_BUSY_VERDICT_S", "600"))
_active_host_runs: Dict[Tuple[str, str], Dict[str, str]] = {}


def _host_key(topology_id: str, host_id: str) -> Tuple[str, str]:
    """Normalization point for the registry key (trim + lower the host id)."""
    return ((topology_id or "").strip(), (host_id or "").strip())


def _parse_iso_ts(raw: str) -> Optional[float]:
    """Parse an ISO-8601 timestamp (with trailing 'Z' or +00:00) to epoch seconds.
    Returns None if unparseable."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _recent_host_verdict_ts(topology_id: str, host_id: str) -> Optional[float]:
    """Most-recent guardrail verdict epoch-seconds across runs on this host.
    Scans every /outputs/<run>/guardrail/run.json for matching topology/host,
    then reads the last ts of that run's verdicts.ndjson.  Restart-surviving:
    if a run is still live in the container (verdicts streaming) this catches it
    even after the in-process registry was wiped."""
    key = _host_key(topology_id, host_id)
    if not key[0] or not key[1]:
        return None
    if not OUTPUTS_DIR.exists():
        return None
    latest: Optional[float] = None
    try:
        children = list(OUTPUTS_DIR.iterdir())
    except Exception:
        return None
    for child in children:
        if not child.is_dir():
            continue
        meta_path = child / "guardrail" / "run.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if _host_key(meta.get("topology_id", ""), meta.get("host_id", "")) != key:
            continue
        vpath = child / "guardrail" / "verdicts.ndjson"
        if not vpath.exists():
            continue
        try:
            # Tail-read the last line only (verdicts files can be large).
            with vpath.open("rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size == 0:
                    continue
                block = b""
                pos = size - 1
                while pos > 0 and block.count(b"\n") < 2:
                    step = min(2048, pos)
                    fh.seek(pos - step)
                    block = fh.read(step) + block
                    pos -= step
                last_line = block.strip().split(b"\n")[-1]
            if not last_line:
                continue
            rec = json.loads(last_line.decode("utf-8", errors="ignore"))
        except Exception:
            continue
        ts = _parse_iso_ts(rec.get("ts") or rec.get("timestamp"))
        if ts is not None and (latest is None or ts > latest):
            latest = ts
    return latest


def _host_busy_state(topology_id: str, host_id: str) -> Dict[str, Any]:
    """Decide whether a host is already running a coder56 engagement.
    Returns {busy, reason, run_id, since, last_verdict_ts}."""
    key = _host_key(topology_id, host_id)
    if not key[0] or not key[1]:
        return {"busy": False, "reason": "", "run_id": "", "since": "",
                "last_verdict_ts": None}

    # Signal 1: in-process registry of live lead-driver tasks.
    entry = _active_host_runs.get(key)
    if entry:
        run_id = entry.get("run_id", "")
        task = _lead_drivers.get(run_id) if run_id else None
        if task and not task.done():
            return {"busy": True, "reason": "lead-driver active",
                    "run_id": run_id, "since": entry.get("since", ""),
                    "last_verdict_ts": _recent_host_verdict_ts(*key)}
        # Stale registry entry (driver already gone): drop it so it can't block.
        _active_host_runs.pop(key, None)

    # Signal 2: recent verdicts for this host (restart-surviving fallback).
    last_ts = _recent_host_verdict_ts(*key)
    if last_ts is not None and (time.time() - last_ts) < BUSY_RECENT_VERDICT_S:
        return {"busy": True, "reason": f"recent guardrail verdict (within {int(BUSY_RECENT_VERDICT_S)}s)",
                "run_id": "", "since": "",
                "last_verdict_ts": last_ts}

    return {"busy": False, "reason": "", "run_id": "",
            "since": "", "last_verdict_ts": last_ts}


def _register_host_run(topology_id: str, host_id: str, run_id: str,
                       container_id: str = "") -> None:
    """Mark a host busy (one run per host).  Idempotent for the same run_id."""
    key = _host_key(topology_id, host_id)
    if not key[0] or not key[1] or not run_id:
        return
    _active_host_runs[key] = {"run_id": run_id, "since": _now_iso(),
                              "container_id": container_id}


def _release_host_run(topology_id: str, host_id: str, run_id: str) -> None:
    """Free a host when its run ends.  Only clears the entry if it still points
    at this run_id (a newer run may have legitimately taken the slot)."""
    key = _host_key(topology_id, host_id)
    entry = _active_host_runs.get(key)
    if entry and entry.get("run_id") == run_id:
        _active_host_runs.pop(key, None)

# Drafting an engagement plan can require a long inference queue on the shared
# provider.  Four minutes was not enough during normal provider load and caused
# the UI to show its generic "declined/unavailable" template prematurely.
# Operators may tune this without a code change; retain a safe 10-minute default.
try:
    LLM_CHAT_TIMEOUT_S = float(os.getenv("LLM_CHAT_TIMEOUT_S", "600"))
except ValueError:
    logger.warning("Invalid LLM_CHAT_TIMEOUT_S; using the 600-second default")
    LLM_CHAT_TIMEOUT_S = 600.0


# =============================================================================
# Path helpers
# =============================================================================

def _guardrail_dir(run_id: str) -> Path:
    return OUTPUTS_DIR / run_id / "guardrail"


def _allocate_run_id(topology_id: str) -> str:
    """Allocate a launch-scoped id.

    A topology/container can host many OpenCode sessions concurrently.  Using
    the container's fixed RUN_ID made simultaneous launches overwrite the same
    manifest and guardrail files.  A timestamp plus random suffix keeps the
    familiar topology prefix while making every launch independent.
    """
    base = re.sub(r"[^A-Za-z0-9_.-]+", "-", topology_id or "isolated").strip("-.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    for _ in range(10):
        candidate = f"{base}-{stamp}-{uuid.uuid4().hex[:8]}"
        if not (OUTPUTS_DIR / candidate).exists():
            return candidate
    raise HTTPException(status_code=503, detail="Could not allocate a unique run id")


def _register_session_run(session_id: str, run_id: str) -> None:
    """Persist the root OpenCode-session -> launch mapping for the guardrail.

    Child phase/verifier sessions inherit this mapping through OpenCode's
    parentID chain, so all commands from one logical run use that run's own
    goal, mode, approvals, verdicts, and RUN_ID environment.
    """
    _valid_token(session_id, "session_id")
    _valid_token(run_id, "run_id")
    _atomic_write(OUTPUTS_DIR / ".session-runs" / f"{session_id}.json", {
        "session_id": session_id,
        "run_id": run_id,
        "registered_at": _now_iso(),
    })


def _approvals_dir(run_id: str) -> Path:
    return _guardrail_dir(run_id) / "approvals"


def _req_path(run_id: str, req_id: str) -> Path:
    return _approvals_dir(run_id) / f"{req_id}.req.json"


def _dec_path(run_id: str, req_id: str) -> Path:
    return _approvals_dir(run_id) / f"{req_id}.dec.json"


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# --- path-safety: run_id / req_id come from the URL and must not escape /outputs.
# The agent-manager backend has no auth dependency (it is an internal lab tool), so
# every filesystem path derived from a path parameter is validated + contained.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _valid_token(value: str, name: str) -> str:
    """Reject anything that isn't a flat safe token. The regex forbids path
    separators; the explicit checks forbid the parent ('..') / self ('.') segments
    that would otherwise let a dot-only token escape the run directory."""
    if (
        not value
        or not _TOKEN_RE.match(value)
        or "/" in value or "\\" in value
        or value in (".", "..")
    ):
        raise HTTPException(status_code=400, detail=f"Invalid {name}")
    return value


def _assert_within(base: Path, target: Path) -> Path:
    """Resolve target and guarantee it stays inside base (no traversal escape)."""
    base_resolved = base.resolve()
    target_resolved = target.resolve()
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError:
        raise HTTPException(status_code=400, detail="Path escapes the allowed directory")
    return target_resolved



def _run_meta_path(run_id: str) -> Path:
    return _guardrail_dir(run_id) / "run.json"


def _read_run_meta(run_id: str) -> Dict[str, Any]:
    """Manifest written at launch: ties a run_id to its container_id + session_id
    (the guardrail, running inside the container, knows neither reliably)."""
    path = _run_meta_path(run_id)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# =============================================================================
# Engagement store
#
# One JSON file per engagement at OUTPUTS_DIR/engagements/<engagement_id>.json.
# Findings are stored INSIDE the engagement JSON (single-file atomic writes,
# trivial report rendering). Runs are linked by id (run_ids) AND by an additive
# `engagement_id` written into each run manifest (OUTPUTS_DIR/<run_id>/guardrail/
# run.json) so the legacy /run/:runId redirect can resolve its engagement in O(1).
# =============================================================================

# Severity ordering for stable display (critical first).
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _engagements_dir() -> Path:
    return OUTPUTS_DIR / "engagements"


def _engagement_path(engagement_id: str) -> Path:
    return _engagements_dir() / f"{engagement_id}.json"


def _report_cache_paths(engagement_id: str) -> tuple:
    """The cached report artifacts for one engagement (html + json)."""
    out_dir = _engagements_dir()
    return (out_dir / f"{engagement_id}.report.html",
            out_dir / f"{engagement_id}.report.json")


def _invalidate_report_cache(engagement_id: str) -> None:
    """Unlink the engagement's cached report.html/report.json so the next
    GET report.html regenerates from the CURRENT findings (8c2f1a postmortem
    defect 4: the client report showed 1 finding while the ledger had 3, and
    a GET hours later still served the stale file). Best-effort, never raises."""
    try:
        for p in _report_cache_paths(engagement_id):
            p.unlink(missing_ok=True)
    except Exception as exc:
        logger.debug("invalidate_report_cache[%s]: %s", engagement_id, exc)


def _read_engagement(engagement_id: str) -> Optional[Dict[str, Any]]:
    path = _engagement_path(engagement_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_engagement(engagement_id: str, data: Dict[str, Any]) -> None:
    _assert_within(OUTPUTS_DIR, _engagement_path(engagement_id))
    _atomic_write(_engagement_path(engagement_id), data)


# Private/reserved IP ranges that are NEVER considered "external/production".
# Recommendation #5: judge_fail=allow must be refused for any target that is
# non-RFC1918 / externally-routable. We treat loopback, link-local, and all of
# RFC1918 (which already covers the lab's 172.25.0.0/x scl-playground bridge
# and the docker/topology bridges) as internal; anything else (a public IP or
# a routable CIDR) is external. Hostnames/URLs with no IP literal are treated
# as conservatively-internal (lab topology hosts are named), because we cannot
# resolve them offline here — the gate is about IP-bearing scopes.
import ipaddress as _ipaddress

_PRIVATE_NETS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("127.0.0.0/8"),     # loopback
    _ipaddress.ip_network("169.254.0.0/16"),  # link-local
]


def _scope_is_external_target(scope: str) -> bool:
    """True if scope contains ANY routable (non-private) IP literal or CIDR.

    Hostnames/URLs without an IP literal return False (cannot classify offline;
    named lab hosts must not be blocked). A single public IP in the scope makes
    the whole engagement 'external'."""
    if not scope:
        return False
    # Extract dotted-quad IPv4 literals and CIDRs (1.2.3.4 or 1.2.3.0/24).
    tokens = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b", scope)
    for tok in tokens:
        try:
            net = _ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if not any(net.subnet_of(priv) for priv in _PRIVATE_NETS):
            return True
    return False


def _engagement_target_is_external(engagement_id: Optional[str]) -> bool:
    """True if the engagement's target_scope names an externally-routable target.

    Returns False when there is no engagement, no scope, or the scope is private
    / hostname-only (the operator-allowable cases)."""
    if not engagement_id:
        return False
    eng = _read_engagement(engagement_id)
    if not eng:
        return False
    return _scope_is_external_target((eng.get("target_scope") or "").strip())


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _load_all_engagements() -> List[Dict[str, Any]]:
    d = _engagements_dir()
    if not d.exists():
        return []
    out: List[Dict[str, Any]] = []
    for child in d.glob("*.json"):
        try:
            out.append(json.loads(child.read_text(encoding="utf-8")))
        except Exception:
            continue
    out.sort(key=lambda e: e.get("updated_at") or e.get("created_at") or "", reverse=True)
    return out


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stable order: severity (critical->info), then title."""
    return sorted(findings, key=lambda f: (_SEV_ORDER.get(str(f.get("severity", "")).lower(), 99),
                                           f.get("title", "")))


def _run_overall_status(meta: Dict[str, Any]) -> str:
    """Derive the user-facing lifecycle from durable manifest state.

    A manifest-level HALT (set by the circuit breaker / no-op detector) takes
    PRECEDENCE over the all-phases-completed derivation: run b1425481 had 4/4
    phases 'completed' yet was a dead-judge failure, so without this override a
    halted run would still surface as 'completed'. An undecided-escalate pause is
    reported as 'awaiting_review' (recoverable operator hold), not 'failed'.
    """
    if not meta.get("accepted"):
        return "awaiting_accept"
    if meta.get("halted") or str(meta.get("status") or "").lower() == "failed":
        return "failed"
    runtime = meta.get("phase_runtime") or []
    if runtime:
        statuses = [str(p.get("status") or "") for p in runtime]
        if statuses and all(status == PhaseStatus.COMPLETED.value for status in statuses):
            return "completed"
        if any(status == PhaseStatus.AWAITING_REVIEW.value for status in statuses):
            return "awaiting_review"
    return "running"


async def _reconcile_planned_run_statuses(engagement_id: str) -> Optional[Dict[str, Any]]:
    """Persist OWASP `done` when its linked run has durably completed.

    This is intentionally restart-safe: the GET engagement path can repair a
    ledger even if the backend restarted between the final phase and the driver's
    completion hook.
    """
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id)
        if not eng:
            return None
        changed = False
        for planned in eng.get("plan") or []:
            if planned.get("status") != PlannedRunStatus.RUNNING.value:
                continue
            run_id = planned.get("run_id") or ""
            meta = _read_run_meta(run_id) if run_id else {}
            if meta and _run_overall_status(meta) == "completed":
                planned["status"] = PlannedRunStatus.DONE.value
                changed = True
        if changed:
            eng["updated_at"] = _now_iso()
            _write_engagement(engagement_id, eng)
        return eng


def _engagement_detail(eng: Dict[str, Any]) -> Dict[str, Any]:
    """Augment an engagement dict with its runs' manifests (for detail/report)."""
    runs: List[Dict[str, Any]] = []
    for rid in eng.get("run_ids", []) or []:
        meta = _read_run_meta(rid)
        if meta:
            # Guarantee a run_id (some older manifests omit it); fall back to the
            # linked id so the UI/report always have a stable identifier.
            meta.setdefault("run_id", rid)
            meta["status"] = _run_overall_status(meta)
            runs.append(meta)
    eng = dict(eng)
    eng["findings"] = _sort_findings(eng.get("findings") or [])
    return {"engagement": eng, "runs": runs, "findings": eng["findings"]}


# =============================================================================
# Per-engagement agent memory
# =============================================================================
# coder56's long-term memory is scoped PER ENGAGEMENT (shared across all
# runs/phases of one engagement, isolated between engagements) — not one global
# file. The agent always reads+appends a stable run-relative path
#   /outputs/<RUN_ID>/memory/MEMORY.md          (the agent expands $RUN_ID)
# which _ensure_run_memory (called on every launch) links to the engagement's
# shared memory file via a relative symlink. Standalone runs (no engagement)
# get a real per-run file at the same path instead of a symlink. All containers
# mount the same host `outputs` dir at /outputs, so a relative symlink created
# here resolves identically inside every agent container.

def _engagement_memory_path(engagement_id: str) -> Path:
    """The shared memory file for an engagement (sibling of <id>.json)."""
    return _engagements_dir() / engagement_id / "MEMORY.md"


def _run_memory_path(run_id: str) -> Path:
    """The stable run-relative path the agent reads/appends."""
    return OUTPUTS_DIR / run_id / "memory" / "MEMORY.md"


def _phase0_complete(engagement_id: Optional[str]) -> bool:
    """Phase 0 is complete enough to advance past when the engagement's shared
    memory carries the THREAT_MODEL| record (fallback: at least TARGET_IDENTITY|).
    The deployed coder56_phase Phase-0 worker emits both per
    PHASE0_TARGET_VALIDATION_BLOCK. Used by the Phase-0 hard guard
    (advance_phase) and the auto-mode nudge (_lead_driver) so glm-5.2 cannot
    skip scoping and dive straight into deep testing (it did on the OpenHospital
    run — TARGET_IDENTITY| was grabbed but no THREAT_MODEL| was emitted)."""
    if not engagement_id:
        return False
    try:
        path = _engagement_memory_path(engagement_id)
        if not path.exists():
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    return ("THREAT_MODEL|" in text) or ("TARGET_IDENTITY|" in text)


def _memory_seed_header(eng: Dict[str, Any]) -> str:
    """Self-describing header for a fresh engagement memory file."""
    name = (eng.get("name") or eng.get("id") or "").strip()
    scope = (eng.get("target_scope") or "").strip()
    obj = (eng.get("objective") or "").strip()
    lines = ["# Engagement Memory", ""]
    if name:
        lines.append(f"**Engagement:** {name}")
    if scope:
        lines.append(f"**Target scope:** {scope}")
    if obj:
        lines.append(f"**Objective:** {obj}")
    eid = (eng.get("id") or "").strip()
    if eid:
        # C1: make the engagement identity explicit so memory is keyed by
        # (engagement, target_fingerprint) and a repointed host is detected.
        lines.append(f"**Engagement id:** {eid}")
    # C1 TARGET-IDENTITY: the fingerprint the phase worker re-checks at each phase
    # boundary (single-line JSON so it is trivially greppable + parseable).
    fp = eng.get("target_fingerprint")
    if isinstance(fp, dict) and fp:
        try:
            lines.append("**TARGET FINGERPRINT:** " + json.dumps(fp, ensure_ascii=False, separators=(",", ":")))
        except Exception:
            pass
    lines += [
        "",
        "_Shared long-term notebook across ALL runs and phases of this "
        "engagement. This is the authoritative memory and live coordination bus: "
        "trust established facts, execute only missing deltas, and use "
        "`[CLAIMED]`/`[DONE]` work ids to prevent parallel duplication. APPEND "
        "ONLY (`>>`); never edit or delete prior entries. Write broadly useful "
        "discoveries immediately, tersely, with target/host and evidence paths._",
        "",
        "<!-- New entries appended below by agents (dated, ISO-UTC). -->",
        "",
    ]
    return "\n".join(lines)


def _ensure_run_memory(engagement_id: Optional[str], run_id: str) -> None:
    """Guarantee the agent's memory file exists and points at the right place
    BEFORE its first bash call. Called on every launch from _finalize_run.

    - engagement run: seed the engagement memory once (never overwrite), then
      (re)create a relative symlink at the run path so append-only writes land
      in the shared engagement file. Re-creating on every launch handles the
      reused fixed `iso-sandbox` run_id being pointed at different engagements,
      and a prior standalone real-file at the same path.
    - standalone run (no engagement / engagement missing): a real per-run file.
    """
    link = _run_memory_path(run_id)
    link.parent.mkdir(parents=True, exist_ok=True)

    eng = _read_engagement(engagement_id) if engagement_id else None
    if eng is None:
        # Standalone run: a real per-run file (not global, not a symlink).
        if not link.exists() and not link.is_symlink():
            _assert_within(OUTPUTS_DIR, link)
            link.write_text(
                "# Run Memory\n\n_Append-only long-term notebook for this run._\n\n",
                encoding="utf-8",
            )
        return

    target = _engagement_memory_path(engagement_id)  # type: ignore[arg-type]
    _assert_within(OUTPUTS_DIR, target)
    # Seed the engagement memory exactly once; never clobber accumulated entries.
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_memory_seed_header(eng), encoding="utf-8")

    # (Re)create the symlink on every launch. Remove a prior symlink OR a prior
    # standalone real-file (the iso-sandbox standalone→engagement transition);
    # a directory here is unexpected — surface it rather than rmtree.
    if os.path.lexists(link):
        if link.is_symlink() or link.is_file():
            os.remove(link)
        else:
            raise RuntimeError(f"Unexpected non-file at memory path {link}")
    rel = os.path.relpath(target, start=link.parent)
    os.symlink(rel, link)


# =============================================================================
# Launch orchestration
# =============================================================================

async def _set_host_guardrail(topology_id: str, host_id: str, enabled: bool) -> bool:
    """Set a host's guardrail_enabled flag and save the topology back to the plugin.

    Returns True if a save was performed, False if the host already had the
    desired value (no save needed — and mode.txt is authoritative at runtime
    anyway). Saves the FULL topology so firewall/infrastructure/router fields are
    preserved (same merge semantics as topologies.update_topology).
    """
    current = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
    topology = current.get("topology", current)
    found = False
    changed = False
    for net in topology.get("networks", []) or []:
        for host in net.get("hosts", []) or []:
            if host.get("id") == host_id:
                found = True
                if bool(host.get("guardrail_enabled")) != enabled:
                    host["guardrail_enabled"] = enabled
                    changed = True
    if not found:
        raise HTTPException(status_code=404, detail=f"Host {host_id} not found in topology {topology_id}")
    if not changed:
        return False
    topology["id"] = topology_id
    await post_to_topology_plugin("/api/topologies", topology)
    return True


async def _host_has_coder56(topology_id: str, host_id: str) -> bool:
    current = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
    topology = current.get("topology", current)
    for net in topology.get("networks", []) or []:
        for host in net.get("hosts", []) or []:
            if host.get("id") == host_id:
                return "coder56" in (host.get("agents") or [])
    return False


async def _wait_for_job(topology_id: str, job_id: Optional[str]) -> Dict[str, Any]:
    """Poll the topology plugin's job until completed/failed (or timeout).

    A missing job_id means the start endpoint did not return an async job — for an
    explicit start that is a failure (we cannot confirm the topology came up), NOT
    an implicit success, so the caller fails the launch rather than proceeding
    against a possibly-not-started topology.
    """
    if not job_id:
        return {"status": "failed", "error": "topology start returned no job_id"}
    deadline = time.time() + POLL_JOB_TIMEOUT_S
    last: Dict[str, Any] = {"status": "running"}
    while time.time() < deadline:
        try:
            data = await fetch_from_topology_plugin(f"/api/jobs/{job_id}")
            last = data.get("job") or {"status": "running"}
        except Exception as exc:  # transient plugin hiccup — keep polling
            logger.debug("job poll transient error: %s", exc)
        status = str(last.get("status", "running")).lower()
        if status in ("completed", "failed", "error"):
            return last
        await asyncio.sleep(POLL_JOB_INTERVAL_S)
    return {"status": "timeout", "error": "job poll timed out", **last}


async def _resolve_container_id(topology_id: str, host_id: str) -> str:
    # Imported lazily to avoid a circular import at module load.
    from .containers import get_container_by_host
    try:
        detail = await get_container_by_host(topology_id, host_id)
        raw_state = detail.container.state
        state = str(getattr(raw_state, "value", raw_state) or "").lower()
        if state != "running":
            raise HTTPException(
                status_code=404,
                detail=f"Container for host {host_id} is not running (state={state or 'unknown'})",
            )
        return detail.container.container_id
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container for host {host_id}: {exc}")


async def _wait_opencode_ready(container_id: str, timeout_s: float = 120.0) -> None:
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import check_opencode_ready_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        res = await check_opencode_ready_async(host=addr, port=4096, timeout=10)
        if res.get("ready") or res.get("healthy"):
            return
        await asyncio.sleep(2.0)
    raise HTTPException(status_code=504, detail="OpenCode server did not become ready in time")


# Egress fix: a freshly-started topology sets each host's default route via the
# topology router gateway (10.77.N.254) which has NO internet egress, so coder56's
# LLM calls hang and the agent wedges "busy" with empty messages. Re-point the
# default route at the shared scl-playground bridge gateway (172.25.0.1, the dev
# holding the 172.* address). Best-effort: never fails the launch (the topology may
# already be egress-fixed, e.g. a long-lived one). See fix_egress in the dataset harness.
_EGRESS_SCRIPT = (
    "set -e; "
    "bif=$(ip -o -4 addr | awk '{print $2,$4}' | grep ' 172\\.' | awk '{print $1}' | head -1); "
    "bip=$(ip -o -4 addr show dev \"$bif\" 2>/dev/null | awk '{print $4}' | head -1); "
    "gw=$(echo \"$bip\" | awk -F. '{print $1\".\"$2\".\"$3\".1\"}'); "
    "ip route replace default via \"$gw\" dev \"$bif\" && echo \"OK $bif $gw\""
)


async def _fix_egress(container_id: str) -> str:
    """Re-point the container's default route at the playground bridge gateway so
    coder56 can reach the LLM endpoint. Returns the 'OK <if> <gw>' line, or '' on
    any failure (best-effort — caller must not abort the launch).

    Uses aiodocker's exec API directly (the shared execute_in_container helper
    predates aiodocker 0.24 and passes kwargs this version rejects)."""
    try:
        async with create_docker_client() as docker_client:
            container = await docker_client.docker.containers.get(container_id)
            exec_inst = await container.exec(cmd=["sh", "-c", _EGRESS_SCRIPT], stdout=True, stderr=True)
            out = b""
            async with exec_inst.start(detach=False) as stream:
                while True:
                    msg = await stream.read_out()
                    if msg is None:
                        break
                    out += msg.data if isinstance(msg.data, bytes) else str(msg.data).encode()
        text = out.decode("utf-8", "replace").strip()
        last = text.splitlines()[-1] if text else ""
        if last.startswith("OK "):
            logger.info("fix_egress[%s]: %s", container_id[:24], last)
            return last
        logger.warning("fix_egress[%s] unexpected output: %r", container_id[:24], text)
        return ""
    except Exception as exc:
        logger.warning("fix_egress[%s] failed: %s", container_id[:24], exc)
        return ""


def _launched_at_epoch_ms(run_id: str, meta: Dict[str, Any]) -> Optional[int]:
    """Resolve the run's launch instant as epoch-MILLIS, the unit opencode.db
    stores in session.time_created (e.g. 1785706219570). launched_at is written
    by _finalize_run as an ISO-8601 string (_now_iso). Returns None if unknown
    (caller then skips filtering rather than risk dropping everything)."""
    raw = meta.get("launched_at") or ""
    if isinstance(raw, (int, float)):
        val = int(raw)
        return val if val > 10_000_000_000 else val * 1000  # seconds->ms heuristic
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except (TypeError, ValueError):
        return None


async def _snapshot_opencode_db(run_id: str) -> None:
    """Persist the run's ephemeral opencode.db (agent transcripts + per-session
    token totals) to OUTPUTS_DIR/<run_id>/opencode.db so it survives host/
    container recreate. Only /outputs is mounted into the run container, so the
    in-container opencode.db is otherwise lost the moment the host is recreated.

    The live container opencode.db is SHARED across every run on that host, so a
    raw `sqlite3 .backup` absorbs earlier runs' sessions (run2 inherited run1's).
    After the backup we therefore (1) keep a FULL unfiltered copy at
    opencode.db.full for forensics and (2) FILTER opencode.db to drop every
    session/message/part whose time_created predates THIS run's launched_at
    (epoch-ms), always keeping the run's own root session. opencode's schema
    cascades session->message/part/session_message/session_input on delete, but
    SQLite has FK enforcement OFF by default and the in-container binary is
    version-variable, so we delete the child rows by their own time_created too
    (belt-and-suspenders) before VACUUM.

    Best-effort: called on every driver exit (lead + phase, incl. review-gate,
    auto-continue completion, stall/timeout/watchdog kill, graceful finalize);
    never raises. run_id is _valid_token-validated (no shell metachars)."""
    try:
        meta = _read_run_meta(run_id)
        container_id = meta.get("container_id", "")
        if not container_id:
            return
        dst_dir = OUTPUTS_DIR / run_id
        root_session = str(meta.get("session_id") or "")
        launched_ms = _launched_at_epoch_ms(run_id, meta)
        # Back up the live (WAL-open) db first, into opencode.db (full).
        backup_script = (
            "set -e; "
            "DST='/outputs/" + run_id + "'; "
            "mkdir -p \"$DST\"; "
            "SRC=/root/.local/share/opencode/opencode.db; "
            "if [ -f \"$SRC\" ]; then "
            "  sqlite3 \"$SRC\" \".backup '$DST/opencode.db'\" && echo SNAP_OK; "
            "else echo SNAP_NODB; fi"
        )
        async with create_docker_client() as docker_client:
            container = await docker_client.docker.containers.get(container_id)
            exec_inst = await container.exec(cmd=["sh", "-c", backup_script], stdout=True, stderr=True)
            out = b""
            async with exec_inst.start(detach=False) as stream:
                while True:
                    msg = await stream.read_out()
                    if msg is None:
                        break
                    out += msg.data if isinstance(msg.data, bytes) else str(msg.data).encode()
        text = out.decode("utf-8", "replace").strip()
        last = text.splitlines()[-1] if text else ""
        if last != "SNAP_OK":
            logger.warning("snapshot_opencode_db[%s]: %s", run_id, text or "(no output)")
            return
        logger.info("snapshot_opencode_db[%s]: saved -> %s", run_id, dst_dir / "opencode.db")

        # Forensic full copy (absorbs all prior host sessions — never filtered).
        if launched_ms is None:
            logger.info("snapshot_opencode_db[%s]: launched_at unknown; skipping per-run filter (full snapshot kept)", run_id)
            return
        try:
            full_path = dst_dir / "opencode.db.full"
            if not full_path.exists():
                # Only keep the first full copy per run (it already contains all
                # prior sessions; later snapshots are subsets of this one).
                (dst_dir / "opencode.db").replace(full_path)
                # Re-backup the filtered source from the live db.
                rebackup = (
                    "set -e; DST='/outputs/" + run_id + "'; "
                    "SRC=/root/.local/share/opencode/opencode.db; "
                    "sqlite3 \"$SRC\" \".backup '$DST/opencode.db'\" && echo FULL_OK;"
                )
                async with create_docker_client() as docker_client:
                    container = await docker_client.docker.containers.get(container_id)
                    ei = await container.exec(cmd=["sh", "-c", rebackup], stdout=True, stderr=True)
                    rb = b""
                    async with ei.start(detach=False) as stream:
                        while True:
                            m = await stream.read_out()
                            if m is None:
                                break
                            rb += m.data if isinstance(m.data, bytes) else str(m.data).encode()
                if (rb.decode("utf-8", "replace").strip().splitlines() or [""])[-1] != "FULL_OK":
                    logger.warning("snapshot_opencode_db[%s]: full-copy rebackup failed; keeping unfiltered snapshot", run_id)
                    return
        except Exception as exc:
            logger.warning("snapshot_opencode_db[%s]: forensic full copy failed (%s); proceeding to filter", run_id, exc)

        # Filter opencode.db to THIS run only: drop rows older than launched_at.
        # root_session (the coder56 lead/launch session) is always retained even
        # if its time_created edge-cases below the threshold. PRAGMA foreign_keys
        # ON enables session->message/part cascade; child deletes are repeated
        # explicitly for FK-off safety. Threshold is an integer literal (epoch-ms
        # from _launched_at_epoch_ms, never user-controlled), and root_session is
        # a _valid_token session id — both safe to interpolate.
        keep_root = f" AND id != '{root_session}'" if root_session else ""
        filter_script = (
            "set -e; DST='/outputs/" + run_id + "/opencode.db'; "
            "sqlite3 \"$DST\" \""
            "PRAGMA foreign_keys=ON; "
            "DELETE FROM session WHERE time_created < " + str(int(launched_ms)) + keep_root + "; "
            "DELETE FROM message WHERE time_created < " + str(int(launched_ms)) + "; "
            "DELETE FROM part WHERE time_created < " + str(int(launched_ms)) + "; "
            "VACUUM; "
            "\" && echo FILTER_OK;"
        )
        fout = b""
        async with create_docker_client() as docker_client:
            container = await docker_client.docker.containers.get(container_id)
            exec_inst = await container.exec(cmd=["sh", "-c", filter_script], stdout=True, stderr=True)
            async with exec_inst.start(detach=False) as stream:
                while True:
                    msg = await stream.read_out()
                    if msg is None:
                        break
                    fout += msg.data if isinstance(msg.data, bytes) else str(msg.data).encode()
        ft = fout.decode("utf-8", "replace").strip()
        if (ft.splitlines() or [""])[-1] == "FILTER_OK":
            logger.info("snapshot_opencode_db[%s]: filtered to sessions since launch (>= %d ms); full copy at opencode.db.full",
                        run_id, launched_ms)
        else:
            logger.warning("snapshot_opencode_db[%s]: filter step output: %s", run_id, ft or "(no output)")
    except Exception as exc:
        logger.warning("snapshot_opencode_db[%s] failed: %s", run_id, exc)


# =============================================================================
# Isolated sandbox (topology-free coder56)
#
# A single long-lived coder56 container on playground-net, reused across
# launches — no topology plugin, no host selection. The ubuntu-24.04-opencode
# image's entrypoint.sh starts the guardrail serve (127.0.0.1:4097) + executor
# opencode serve (0.0.0.0:4096) + SSH, and copies the baked opencode.json (which
# already carries the coder56 agent + top-level tools.bash:false). So the sandbox
# needs only the right env + volumes + network — no init script. One sandbox ==
# one fixed RUN_ID; each launch writes a fresh mode.txt/goal.txt + opens a new
# opencode session into the same container (same reuse semantics as a long-lived
# topology host). Outputs persist on the host bind-mount across restarts.
# =============================================================================

SANDBOX_IMAGE = os.environ.get("CODER56_SANDBOX_IMAGE", "ubuntu-24.04-opencode:0.1")
SANDBOX_NETWORK = os.environ.get("SCL_NETWORK_NAME", "playground-net")


def _sandbox_name() -> str:
    return os.environ.get("CODER56_SANDBOX_NAME", "coder56-sandbox")


def _sandbox_run_id() -> str:
    # Also used as the container's scl.topology label so resolve_run_id() finds it.
    return os.environ.get("CODER56_SANDBOX_RUN_ID", "iso-sandbox")


async def _resolve_host_outputs_path() -> str:
    """Bind-mount sources are resolved on the DOCKER HOST, so to give the sandbox
    the same /outputs the backend reads we must discover the host path behind the
    dashboard container's own /outputs mount. Self-inspect and return that mount's
    Source. Fallbacks: OUTPUTS_HOST_PATH env, then the in-container /outputs."""
    override = os.environ.get("OUTPUTS_HOST_PATH")
    if override:
        return override
    self_name = os.environ.get("AGENT_MANAGER_CONTAINER_NAME", "scl-agent-manager-dashboard")
    try:
        async with create_docker_client() as dc:
            container = await dc.docker.containers.get(self_name)
            info = await container.show()
        for m in info.get("Mounts") or []:
            if (m.get("Destination") or "") == "/outputs":
                src = m.get("Source")
                if src:
                    return src
    except Exception as exc:
        logger.warning("sandbox: could not self-inspect %s for /outputs mount: %s", self_name, exc)
    return "/outputs"


def _resolve_agents_host_path() -> str:
    return os.environ.get("AGENTS_HOST_PATH", "/agent-scripts")


def _sandbox_env() -> Dict[str, str]:
    """Environment for the sandbox container. Mirrors the topology coder56 host
    (generate_compose) so the baked entrypoint + opencode.json behave identically.
    Guardrail is ALWAYS armed (GUARDRAIL_ENABLED=1); mode.txt governs per-launch
    strictness (low = pass-through)."""
    return {
        "OPENCODE_API_KEY": os.environ.get("OPENCODE_API_KEY", ""),
        "LLM_URL": os.environ.get("LLM_URL", "https://llm.ai.e-infra.cz/v1"),
        "LLM_MODEL": os.environ.get("LLM_MODEL", "glm-5.2"),
        "SSH_COMPROMISED_USER": "labuser",
        "SSH_COMPROMISED_PASS": os.environ.get("SSH_COMPROMISED_PASS", "strato"),
        "TRIDENT_HOME": "/outputs",
        "RUN_ID": _sandbox_run_id(),
        "GUARDRAIL_ENABLED": "1",
        "GUARDRAIL_PROFILE": "coder56",
        # goal.txt (written per-launch by _finalize_run) is authoritative; this is
        # only the fallback scope the entrypoint bakes into the container env.
        "GUARDRAIL_GOAL": os.environ.get("CODER56_GUARDRAIL_GOAL", ""),
        "GUARDRAIL_HTTP_URL": "http://127.0.0.1:4097",
    }


async def _sandbox_status() -> SandboxStatus:
    name = _sandbox_name()
    try:
        async with create_docker_client() as dc:
            container = await dc.docker.containers.get(name)
            info = await container.show()
    except Exception:
        return SandboxStatus(exists=False, running=False, name=name,
                             run_id=_sandbox_run_id(), image=SANDBOX_IMAGE, status_text="missing")
    state = info.get("State") or {}
    running = bool(state.get("Running"))
    status_text = "running" if running else (state.get("Status") or "stopped")
    return SandboxStatus(
        exists=True, running=running,
        container_id=info.get("Id", ""), name=name,
        run_id=_sandbox_run_id(),
        image=(info.get("Config") or {}).get("Image", SANDBOX_IMAGE),
        created_at=info.get("Created", ""),
        status_text=status_text,
    )


async def _ensure_sandbox() -> str:
    """Create the sandbox container if missing, (re)connect it to the shared
    network, and start it if stopped. Idempotent. Returns the container id."""
    name = _sandbox_name()
    outputs_host = await _resolve_host_outputs_path()
    agents_host = _resolve_agents_host_path()
    env = _sandbox_env()
    async with create_docker_client() as dc:
        try:
            container = await dc.docker.containers.get(name)
        except Exception:
            container = None
        if container is None:
            labels = {
                "scl.plugin": "isolated-coder56",
                "scl.topology": _sandbox_run_id(),  # resolve_run_id() reads this
                "scl.host": "sandbox",
                "scl.isolated": "true",
            }

            def _config(binds: List[str]) -> Dict[str, Any]:
                return {
                    "Image": SANDBOX_IMAGE,
                    # No Cmd override: the image ENTRYPOINT (entrypoint.sh) starts SSH,
                    # the guardrail serve (4097), the executor opencode serve (4096),
                    # copies the baked opencode.json, then idles on tail -f /dev/null.
                    "Env": [f"{k}={v}" for k, v in env.items()],
                    "Labels": labels,
                    "HostConfig": {"CapAdd": ["NET_ADMIN"], "Binds": binds},
                }

            # The agents bind is optional (the coder56 prompt is baked into the
            # image's opencode.json); retry without it if the host path is absent.
            binds = [f"{agents_host}:/app/agents:ro", f"{outputs_host}:/outputs"]
            try:
                container = await dc.docker.containers.create(_config(binds), name=name)
            except Exception as exc:
                logger.warning("sandbox: create with agents bind failed (%s); retrying without", exc)
                try:
                    container = await dc.docker.containers.create(
                        _config([f"{outputs_host}:/outputs"]), name=name)
                except Exception as exc2:
                    raise HTTPException(status_code=500,
                                        detail=f"Could not create sandbox container: {exc2}")
            logger.info("sandbox: created container %s (image %s, run_id %s)",
                        name, SANDBOX_IMAGE, _sandbox_run_id())
        # Best-effort: ensure it's reachable by name over the shared network
        # (idempotent — connecting an already-attached container is a benign error).
        try:
            net = await dc.docker.networks.get(SANDBOX_NETWORK)
            await net.connect({"Container": name})
        except Exception as exc:
            logger.debug("sandbox: network %s connect skipped: %s", SANDBOX_NETWORK, exc)
        info = await container.show()
        if not (info.get("State") or {}).get("Running"):
            await container.start()
            logger.info("sandbox: started container %s", name)
        info = await container.show()
        return info.get("Id") or name


async def _remove_sandbox() -> None:
    name = _sandbox_name()
    async with create_docker_client() as dc:
        try:
            container = await dc.docker.containers.get(name)
        except Exception:
            return  # already gone
        try:
            await container.stop()
        except Exception:
            pass
        try:
            await container.delete(force=True)
            logger.info("sandbox: removed container %s (outputs retained on host)", name)
        except Exception as exc:
            logger.warning("sandbox: delete failed: %s", exc)


async def _restart_sandbox() -> None:
    # Fresh container (opencode state reset); outputs persist on the host bind-mount.
    await _remove_sandbox()
    await _ensure_sandbox()


@router.get("/sandbox", response_model=SandboxStatus)
async def sandbox_status_endpoint() -> SandboxStatus:
    return await _sandbox_status()


@router.post("/sandbox/ensure", response_model=SandboxStatus)
async def sandbox_ensure_endpoint() -> SandboxStatus:
    await _ensure_sandbox()
    return await _sandbox_status()


@router.post("/sandbox/restart", response_model=SandboxStatus)
async def sandbox_restart_endpoint() -> SandboxStatus:
    await _restart_sandbox()
    return await _sandbox_status()


@router.delete("/sandbox", response_model=SandboxStatus)
async def sandbox_remove_endpoint() -> SandboxStatus:
    await _remove_sandbox()
    return await _sandbox_status()


async def _launch_isolated(req: LaunchRequest) -> LaunchResponse:
    """Topology-free launch into the persistent coder56 sandbox."""
    # Same engagement-link validation as the topology path (up front, before the
    # potentially slow sandbox bring-up).
    if req.engagement_id:
        _valid_token(req.engagement_id, "engagement_id")
        if not _read_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail=f"Engagement {req.engagement_id} not found")

    container_id = await _ensure_sandbox()
    return await _finalize_run(
        req, container_id,
        topology_id="isolated", host_id=_sandbox_name(), isolated=True,
    )


async def _finalize_run(req: LaunchRequest, container_id: str, *, topology_id: str,
                        host_id: str, isolated: bool) -> LaunchResponse:
    """Shared launch tail (SCL-independent): wait for opencode, fix egress, write
    mode.txt/goal.txt, create the coder56 session, write the run manifest, and link
    the engagement. Both the topology path and the isolated sandbox path resolve a
    container_id then call this.  The container RUN_ID is only a legacy fallback;
    every launch receives its own id so multiple sessions on one host cannot
    overwrite each other's state."""
    await _wait_opencode_ready(container_id)
    # Best-effort egress fix. Topology hosts route via a no-egress gw and need this;
    # the sandbox on playground-net already has NAT egress, so it's a no-op there.
    await _fix_egress(container_id)

    run_id = _allocate_run_id(topology_id)

    # mode.txt + goal.txt BEFORE create_session so both precede the agent's first
    # bash call. Written DIRECTLY to the resolved run_id (not via helpers that
    # re-resolve run_id) so the guardrail's mode and its authoritative scope share
    # exactly one directory — no first-command race, no run_id divergence.
    mode_dir = _guardrail_dir(run_id)
    mode_dir.mkdir(parents=True, exist_ok=True)
    (mode_dir / "mode.txt").write_text(req.criticality.value, encoding="utf-8")
    # Judge-unavailable fallback (default "escalate" = hold for operator review).
    # Live-toggleable per run via PATCH /runs/{run_id}/judge-fail; the guardrail
    # reads it fresh every command alongside mode.txt, so a console flip takes
    # effect immediately without recreating the host.
    (mode_dir / "judge_fail.txt").write_text("escalate", encoding="utf-8")
    (mode_dir / "goal.txt").write_text(
        f"\n--- directive ---\n{req.directive.strip()}\n", encoding="utf-8"
    )

    # Guarantee the per-engagement memory link/file exists BEFORE the agent's
    # first bash call (same pre-session window as mode.txt/goal.txt above).
    _ensure_run_memory(req.engagement_id, run_id)

    # Create the coder56 session (the directive itself is NOT sent here — the
    # operator must ACCEPT it first via POST /runs/{run_id}/accept).
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import (
        create_session_async, send_prompt_async, _ensure_network_connectivity,
    )
    from ..services.state_manager import get_state_manager

    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")

    create_res = await create_session_async(host=addr, port=4096, title=req.directive[:50])
    if not create_res.get("success"):
        raise HTTPException(status_code=502, detail=f"Failed to create OpenCode session: {create_res.get('error')}")
    session_id = create_res.get("session_id")
    if not session_id:
        raise HTTPException(status_code=502, detail="OpenCode created a session without an id")

    # Must exist before /accept can send the first prompt.  The guardrail resolves
    # this root mapping (and follows parentID for phase/verifier children) before
    # it handles the session's first bash call.
    _register_session_run(session_id, run_id)

    # Register in the state manager (best-effort) so /api/sessions sees it too.
    try:
        sm = get_state_manager()
        sm.create_session(session_id, {
            "container_id": container_id, "host_id": host_id,
            "agent_type": AgentType.CODER56.value, "state": "running",
            "metrics": {"total_messages": 0, "total_tokens_used": 0,
                        "execution_time_seconds": 0.0, "tool_calls_count": 0},
        })
    except Exception:
        pass

    # Option A: an objective-only launch (no drafted phases) still runs as a
    # structural threat-model-driven native_subagents engagement. Synthesize the
    # default Phase 0..3 skeleton so the run goes through coder56_lead + Phase 0 +
    # _lead_driver + finalization, instead of degrading to legacy single-shot
    # (which bypassed the entire methodology restructure). run_planned_run always
    # passes non-empty phases, so it is unaffected. The empty-phases skeleton is
    # MODE-SELECTED (NETWORK = _default_threatmodel_phases, unchanged; API/WEBAPP
    # = the OWASP WSTG v4.2 spine from _default_api_phases/_default_webapp_phases,
    # each leading with a recon-first Phase R). Explicitly drafted phases keep
    # their own mode-appropriate skeletons (drafted upstream); this only fires
    # when req.phases is empty.
    _emode = req.engagement_mode or EngagementMode.NETWORK
    if list(req.phases):
        run_phases = _dedup_phase_plan(list(req.phases))
    elif _emode == EngagementMode.API:
        run_phases = _dedup_phase_plan(_default_api_phases(req.directive))
    elif _emode == EngagementMode.WEBAPP:
        run_phases = _dedup_phase_plan(_default_webapp_phases(req.directive))
    else:
        run_phases = _dedup_phase_plan(_default_threatmodel_phases(req.directive))

    _atomic_write(_run_meta_path(run_id), {
        "run_id": run_id,
        "container_id": container_id,
        "session_id": session_id,
        "topology_id": topology_id,
        "host_id": host_id,
        "isolated": isolated,
        "criticality": req.criticality.value,
        # Operator-selected planner frame (NETWORK default = byte-for-byte no
        # regression). Persisted into the manifest so the empty-phases fallback
        # and _dedup_phase_plan (where req is out of scope) read it back from
        # meta, not from req again.
        "engagement_mode": _emode.value,
        # Guardrail judge-unavailable fallback (live-toggled via judge_fail.txt;
        # mirrored here so the console can display the current value).
        "judge_fail": "escalate",
        "launched_at": _now_iso(),
        "directive": req.directive,
        "accepted": False,
        # Per-phase orchestration. `phases` is the operator's chain (empty =>
        # legacy single-shot). `current_phase` = -1 until accept starts phase 0.
        "phases": [p.dict() for p in run_phases],
        "phase_mode": req.phase_mode.value,
        # P2-6: backend session-per-phase path removed; all phased runs use
        # native_subagents (coder56_lead spawns coder56_phase children). Pinned
        # here regardless of the request value so a stale default or an old
        # frontend payload can't resurrect the top-level coder56-session path.
        "orchestration": Orchestration.NATIVE_SUBAGENTS.value,
        "current_phase": -1,
        "phase_runtime": [
            {"index": i, "status": PhaseStatus.PENDING.value,
             "objective": p.objective, "tactic_id": p.tactic_id,
             "technique_ids": list(p.technique_ids), "session_id": "",
             "result": "", "started_at": "", "completed_at": ""}
            for i, p in enumerate(run_phases)
        ],
        # Additive engagement link (absent on legacy runs). Lets the legacy
        # /run/:runId redirect resolve its engagement without scanning files.
        "engagement_id": req.engagement_id,
    })

    # Container-busy guard: lock this host to the new run the instant its manifest
    # is written (the shared launch tail for topology + isolated paths). A
    # subsequent launch on the same (topology_id, host_id) will hit the 409 gate
    # in launch()/_finalize_run until the lead-driver releases it. Released on
    # driver exit (see _lead_driver) and cleared if the task is already gone.
    _register_host_run(topology_id, host_id, run_id, container_id)

    # Register the run under its engagement (if any): append run_id to run_ids.
    if req.engagement_id:
        async with _engagement_lock(req.engagement_id):
            eng = _read_engagement(req.engagement_id)
            if eng:
                if run_id not in (eng.get("run_ids") or []):
                    eng["run_ids"] = (eng.get("run_ids") or []) + [run_id]
                    eng["updated_at"] = _now_iso()
                    _write_engagement(req.engagement_id, eng)

    return LaunchResponse(
        run_id=run_id,
        session_id=session_id,
        container_id=container_id,
        topology_id=topology_id,
        host_id=host_id,
        criticality=req.criticality,
        message=f"Prepared coder56 ({req.criticality.value}); awaiting acceptance of the initial directive.",
    )


@router.post("/launch", response_model=LaunchResponse)
async def launch(req: LaunchRequest) -> LaunchResponse:
    """Launch a coder56 pentest run at the chosen criticality.

    Sequence (resolves the async-start + first-command-race hazards):
      1. validate the host has coder56 assigned
      2. set host.guardrail_enabled = (criticality != low); save topology
      3. start the topology (async job) and poll to completion
      4. wait for the OpenCode server (and the guardrail runtime) to be ready
      5. resolve run_id from the live container
      6. write mode.txt = criticality  (BEFORE the first command runs)
      7. create the coder56 session with the compiled directive (also forwards
         goal.txt), which sends the agent its objective

    Isolated mode (req.isolated=True) skips steps 1-3 entirely and launches into
    the persistent coder56 sandbox (no topology, no host). See _launch_isolated.
    """
    if req.isolated:
        return await _launch_isolated(req)

    # Topology path: topology_id + host_id are required.
    if not (req.topology_id and req.host_id):
        raise HTTPException(
            status_code=400,
            detail="topology_id and host_id are required (use isolated=true for a topology-free launch).",
        )

    if not await _host_has_coder56(req.topology_id, req.host_id):
        raise HTTPException(
            status_code=409,
            detail=f"Host {req.host_id} has no coder56 agent assigned. Assign coder56 first.",
        )

    # Container-busy guard (one-run-per-host).  Refuse BEFORE the (slow) topology
    # bring-up so a second launch never starts on a host that already has a live
    # run.  A second concurrent run would clobber the shared per-host guardrail
    # state + lead session; the operator must wait or queue.
    busy = _host_busy_state(req.topology_id, req.host_id)
    if busy.get("busy"):
        run_id = busy.get("run_id") or "(detected via recent verdicts)"
        since = busy.get("since") or ""
        suffix = f" since {since}" if since else ""
        raise HTTPException(
            status_code=409,
            detail=(f"A run is already active on host {req.host_id} "
                    f"(topology {req.topology_id}){suffix}: {busy.get('reason')} "
                    f"[run {run_id}]. Wait for it to finish or queue the new run."),
            headers={"X-Busy-Run-Id": run_id, "X-Busy-Since": since,
                     "X-Busy-Reason": busy.get("reason", "")},
        )

    # Optional engagement link: validate the token (path-safety) and confirm the
    # engagement exists before the (expensive) topology bring-up.
    if req.engagement_id:
        _valid_token(req.engagement_id, "engagement_id")
        if not _read_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail=f"Engagement {req.engagement_id} not found")

    guarded = req.criticality != Criticality.LOW
    # Best-effort: persist guardrail_enabled so the plugin LOADS the guardrail for
    # medium/high. Runtime strictness is governed by mode.txt (authoritative), so a
    # save failure here must NOT abort the launch — the guardrail may already be
    # armed (common case) and mode.txt will still drive behavior.
    try:
        await _set_host_guardrail(req.topology_id, req.host_id, guarded)
    except HTTPException:
        if guarded:
            logger.warning("guardrail_enabled save failed for %s/%s; proceeding (mode.txt is authoritative)",
                           req.topology_id, req.host_id)
        # For low we don't need the plugin armed (mode.txt=low short-circuits).
    except Exception as exc:
        logger.warning("guardrail_enabled save error for %s/%s: %s; proceeding", req.topology_id, req.host_id, exc)

    if req.auto_start_topology:
        # Skip the restart when the coder56 host is already up — the plugin's
        # start can report failure on an already-running topology (e.g. an exited
        # sibling container: "container <id> is not running") even though the
        # target host is healthy. Reusing the running topology is what we want.
        try:
            already_up = await _resolve_container_id(req.topology_id, req.host_id)
        except Exception:
            already_up = None
        if already_up:
            logger.info("launch: %s/%s already running (container %s); skipping topology start",
                        req.topology_id, req.host_id, str(already_up)[:16])
        else:
            try:
                start_data = await post_to_topology_plugin(f"/api/topologies/{req.topology_id}/start")
                job = await _wait_for_job(req.topology_id, start_data.get("job_id"))
                if str(job.get("status", "")).lower() in ("failed", "error", "timeout"):
                    # Non-fatal: a start job can fail on a zombie sibling while the
                    # target host still comes up. Let _wait_opencode_ready be the
                    # authoritative readiness gate instead of hard-failing here.
                    logger.warning("launch: topology start job %s: %s; continuing (opencode readiness will gate)",
                                   job.get("status"), str(job.get("error") or "")[:160])
            except Exception as exc:
                logger.warning("launch: topology start error for %s: %s; continuing (opencode readiness will gate)",
                               req.topology_id, exc)

    container_id = await _resolve_container_id(req.topology_id, req.host_id)
    return await _finalize_run(
        req, container_id,
        topology_id=req.topology_id, host_id=req.host_id, isolated=False,
    )


# =============================================================================
# Approvals
# =============================================================================

def _read_req(run_id: str, req_id: str) -> Optional[Dict[str, Any]]:
    path = _req_path(run_id, req_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_dec(run_id: str, req_id: str) -> Optional[Dict[str, Any]]:
    path = _dec_path(run_id, req_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _req_to_model(run_id: str, raw: Dict[str, Any]) -> ApprovalReq:
    gv = raw.get("guardrail_verdict") or {}
    dec_raw = _read_dec(run_id, raw.get("id", ""))
    return ApprovalReq(
        id=raw.get("id", ""),
        ts=raw.get("ts", ""),
        run_id=raw.get("run_id", run_id),
        session_id=raw.get("session_id", ""),
        container_id=raw.get("container_id", ""),
        command=raw.get("command", ""),
        profile=raw.get("profile", "coder56"),
        mode=raw.get("mode", "medium"),
        trigger=raw.get("trigger", "flagged"),
        guardrail_verdict=gv,  # ApprovalGuardrailVerdict accepts the dict subset
        goal=raw.get("goal", ""),
        trace=raw.get("trace", ""),
        parsed_via=raw.get("parsed_via", ""),
        failure_reason=raw.get("failure_reason", ""),
        status=raw.get("status", "pending"),
        seq=int(raw.get("seq", 0) or 0),
        decision=ApprovalDecision(**dec_raw) if dec_raw else None,
    )


def _scan_approvals(run_id: str) -> List[ApprovalReq]:
    d = _approvals_dir(run_id)
    if not d.exists():
        return []
    out: List[ApprovalReq] = []
    for req_file in sorted(d.glob("*.req.json")):
        try:
            raw = json.loads(req_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        req_id = raw.get("id", req_file.stem)
        has_dec = _dec_path(run_id, req_id).exists()
        # Status: decided if a decision file exists; else honor req.status.
        if has_dec:
            raw = dict(raw)
            raw["status"] = "decided"
        out.append(_req_to_model(run_id, raw))
    return out


@router.get("/runs/{run_id}/approvals")
async def list_approvals(run_id: str) -> Dict[str, Any]:
    _valid_token(run_id, "run_id")
    items = _scan_approvals(run_id)
    pending = [a for a in items if a.status == "pending"]
    decided = [a for a in items if a.status != "pending"]
    decided.sort(key=lambda a: a.seq, reverse=True)
    return {
        "run_id": run_id,
        "pending": pending,
        "decided": decided[:50],
        "counts": {"pending": len(pending), "decided": len(decided)},
    }


def _find_req(req_id: str, run_id: Optional[str]) -> Optional[tuple[str, Dict[str, Any]]]:
    """Locate a req by id, optionally scoped to a run. Returns (run_id, raw)."""
    run_ids = [run_id] if run_id else [p.parent.parent.name for p in OUTPUTS_DIR.glob("*/guardrail/approvals")]
    for rid in run_ids:
        if not rid or rid == "guardrail":
            continue
        raw = _read_req(rid, req_id)
        if raw:
            return rid, raw
    return None


@router.post("/approvals/{req_id}/decide")
async def decide(req_id: str, req: DecideRequest) -> Dict[str, Any]:
    _valid_token(req_id, "req_id")
    if req.run_id:
        _valid_token(req.run_id, "run_id")
    if req.action not in ("approve", "reject", "modify", "guide"):
        raise HTTPException(status_code=400, detail="action must be approve|reject|modify|guide")
    if req.action == "modify" and not (req.modified_command and req.modified_command.strip()):
        raise HTTPException(status_code=400, detail="modify requires modified_command")
    if req.action == "guide" and not (req.feedback and req.feedback.strip()):
        raise HTTPException(status_code=400, detail="guide requires feedback")

    found = _find_req(req_id, req.run_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"Approval request {req_id} not found")
    run_id, raw = found

    if str(raw.get("status", "pending")).lower() == "expired":
        return {"status": "expired", "id": req_id, "message": "request already expired; decision ignored"}

    # Atomic, EXCLUSIVE decision write: O_CREAT|O_EXCL guarantees a single writer
    # wins (closes the check-then-act TOCTOU so a double-click/retry cannot
    # overwrite a prior decision). The guardrail reads the dec file once and acts
    # once, so this also bounds execution to a single decision.
    dec = {
        "id": req_id,
        "ts": _now_iso(),
        "decided_ts": _now_iso(),
        "action": req.action,
        "modified_command": req.modified_command,
        "feedback": req.feedback,
        "decided_by": "operator",
    }
    dec_path = _dec_path(run_id, req_id)
    dec_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dec, indent=2).encode("utf-8")
    try:
        fd = os.open(dec_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        return {"status": "already_decided", "id": req_id, "run_id": run_id}
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    # NOTE: we intentionally do NOT rewrite the guardrail-authored req.json (that
    # would race guardrail.ts's markExpired). Decided-ness is derived solely from
    # the presence of <id>.dec.json (see _scan_approvals).
    return {"status": "decided", "id": req_id, "action": req.action, "run_id": run_id}


# =============================================================================
# Verdicts + messages + guide
# =============================================================================

def _accept_prompt(meta: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the EXACT prompt (+ target agent) that accept_initial_directive
    will send to coder56 for this run, so the operator's review gate can display
    the real, complete prompt that reaches the agent — never a divergent or
    stripped mirror of it.

    Branch logic mirrors accept_initial_directive exactly (native_subagents lead
    prompt / backend session-per-phase phase-0 prompt / legacy single-shot).
    Pure (no I/O); safe to call from GET /runs/{id}/meta. Forward references to
    _compile_lead_directive / _compile_phase_directive are fine: this is only
    invoked at request time, after the whole module is loaded."""
    directive = (meta.get("directive") or "").strip()
    phases = meta.get("phases") or []
    if phases:
        orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
        if orch == Orchestration.NATIVE_SUBAGENTS.value:
            return {"accept_prompt": _compile_lead_directive(meta),
                    "accept_agent": "coder56_lead", "accept_path": "native_subagents"}
        # Backend session-per-phase: the phase-0 prompt (no prior findings yet).
        spec = phases[0] or {}
        objective = (spec.get("objective") or "").strip() \
            or f"Execute phase 1 of the authorized engagement (see full directive)."
        prompt = _compile_phase_directive(directive, 0, len(phases), objective, prior_findings=None)
        return {"accept_prompt": prompt, "accept_agent": AgentType.CODER56.value,
                "accept_path": "backend_sessions"}
    return {"accept_prompt": directive, "accept_agent": AgentType.CODER56.value,
            "accept_path": "single_shot"}


@router.get("/runs/{run_id}/meta")
async def get_run_meta(run_id: str) -> Dict[str, Any]:
    """Return the launch manifest (run.json): container_id, session_id,
    criticality, directive, accepted. Lets the console recover state after a
    reload (important for low-criticality runs, which produce no approval files)."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found; has the run been launched?")
    # Surface the EXACT prompt that accept will send, so the review gate shows
    # what truly reaches the agent. Computed live (never persisted to run.json).
    try:
        meta.update(_accept_prompt(meta))
    except Exception as exc:  # never let preview computation break a meta read
        logger.debug("accept_prompt preview failed for %s: %s", run_id, exc)
    return meta


@router.post("/runs/{run_id}/accept")
async def accept_initial_directive(run_id: str) -> Dict[str, Any]:
    """Operator ACCEPTS the initial engagement directive — the one gate between
    'launch prepared the run' and 'coder56 actually receives its objective'.

    launch() arms the guardrail mode + goal and creates the session but does NOT
    send the directive; the agent stays idle until this endpoint is called. The
    directive sent is exactly the one stored in the manifest (what the operator
    reviewed). Idempotent: a second call is a no-op.
    """
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found; has the run been launched?")
    if meta.get("accepted"):
        return {"status": "already_accepted", "run_id": run_id, "session_id": meta.get("session_id", "")}

    directive = meta.get("directive") or ""
    session_id = meta.get("session_id", "")
    container_id = meta.get("container_id", "")
    if not session_id or not container_id:
        raise HTTPException(status_code=409, detail="Run manifest has no session/container; re-launch.")
    if not directive.strip():
        raise HTTPException(status_code=409, detail="No directive stored to accept.")

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import send_prompt_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    phases = meta.get("phases") or []
    if phases:
        orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
        if orch == Orchestration.NATIVE_SUBAGENTS.value:
            # Native subagent coordination: ONE coder56_lead session drives the
            # engagement, spawning a coder56_phase subagent per phase via the Task
            # tool. Send the coordination prompt; the lead-driver watches the
            # Lead session and derives phase_runtime from its task-tool calls.
            lead_prompt = _compile_lead_directive(meta)
            res = await send_prompt_async(
                session_id=session_id, prompt=lead_prompt, host=addr, port=4096,
                agent="coder56_lead", async_mode=True, timeout=30,
            )
            if not res.get("success"):
                raise HTTPException(status_code=502, detail=f"Failed to send lead directive: {res.get('error')}")
            meta = _read_run_meta(run_id)
            meta["accepted"] = True
            meta["accepted_at"] = _now_iso()
            meta["current_phase"] = 0
            _atomic_write(_run_meta_path(run_id), meta)
            _arm_lead_driver(run_id)
            return {"status": "sent", "run_id": run_id, "session_id": session_id,
                    "phased": True, "orchestration": "native_subagents"}
        # Backend session-per-phase (default): start phase 0 in its own session and
        # arm the driver that detects turn-end and gates between phases. The launch
        # session (meta.session_id) stays idle; each phase gets its own.
        await _start_phase(run_id, 0, addr)
        meta = _read_run_meta(run_id)
        meta["accepted"] = True
        meta["accepted_at"] = _now_iso()
        _atomic_write(_run_meta_path(run_id), meta)
        _arm_driver(run_id)
        rt0 = (meta.get("phase_runtime") or [{}])[0]
        return {"status": "sent", "run_id": run_id, "session_id": rt0.get("session_id", session_id), "phased": True}

    # Legacy single-shot: send the whole directive to the launch session.
    res = await send_prompt_async(
        session_id=session_id, prompt=directive, host=addr, port=4096,
        agent=AgentType.CODER56.value, async_mode=True, timeout=30,
    )
    accepted = bool(res.get("success"))
    # Persist accepted state (only flip to true on a successful send).
    meta["accepted"] = accepted
    meta["accepted_at"] = _now_iso() if accepted else ""
    _atomic_write(_run_meta_path(run_id), meta)
    if not accepted:
        raise HTTPException(status_code=502, detail=f"Failed to send directive to coder56: {res.get('error')}")
    # Legacy single-shot has no driver (no _lead_driver / _phase_driver), so it
    # has no natural exit hook. Arm a one-shot finalizer that waits for the
    # coder56 session's turn to go idle (or times out) then snapshots once —
    # covers the legacy path's ephemeral opencode.db the same way the drivers do.
    _arm_legacy_finalizer(run_id)
    return {"status": "sent", "run_id": run_id, "session_id": session_id}



@router.get("/runs/{run_id}/verdicts")
async def get_verdicts(run_id: str, limit: int = Query(default=100, ge=1, le=1000)) -> Dict[str, Any]:
    _valid_token(run_id, "run_id")
    path = _guardrail_dir(run_id) / "verdicts.ndjson"
    if not path.exists():
        return {"run_id": run_id, "verdicts": []}
    lines = path.read_text(encoding="utf-8").splitlines()
    out: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return {"run_id": run_id, "verdicts": out}


@router.get("/runs/{run_id}/messages")
async def get_messages(run_id: str, session_id: str = Query(...)) -> Dict[str, Any]:
    """Agent message stream for a session. Resolves the container from the run
    manifest (run.json) written at launch."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    container_id = meta.get("container_id", "")
    if not container_id:
        raise HTTPException(status_code=404, detail="No container found for run; start the run first.")

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import get_session_messages_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    res = await get_session_messages_async(session_id=session_id, host=addr, port=4096)
    return {"run_id": run_id, "session_id": session_id, "messages": res.get("messages", []) if res.get("success") else []}


@router.post("/runs/{run_id}/guide")
async def guide(run_id: str, req: GuideRequest) -> Dict[str, Any]:
    """Send a free-form operator follow-up prompt to the agent session.

    Guidance is sent to the AGENT only — it is deliberately NOT appended to the
    guardrail's goal.txt, because goal.txt is the guardrail's AUTHORITATIVE scope.
    Folding free-form operator text into it would let guidance widen the enforced
    scope mid-run (a scope-injection bypass). The scope stays = the launch directive.
    """
    _valid_token(run_id, "run_id")
    if not req.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt is required")
    meta = _read_run_meta(run_id)
    session_id = meta.get("session_id", "")
    container_id = meta.get("container_id", "")
    # For phased runs, steer the CURRENT phase's session (the launch session is idle).
    cur = meta.get("current_phase", -1)
    rt = meta.get("phase_runtime") or []
    if 0 <= cur < len(rt) and rt[cur].get("session_id"):
        session_id = rt[cur]["session_id"]
    if not container_id or not session_id:
        raise HTTPException(status_code=404, detail="No container/session found for run.")

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import send_prompt_async, _ensure_network_connectivity
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    res = await send_prompt_async(
        session_id=session_id, prompt=req.prompt, host=addr, port=4096,
        agent="coder56", async_mode=False, timeout=120,
    )
    return {"status": "sent" if res.get("success") else "error",
            "session_id": session_id, "error": res.get("error")}


@router.patch("/runs/{run_id}/judge-fail")
async def set_judge_fail(run_id: str, req: JudgeFailRequest) -> Dict[str, Any]:
    """Live-toggle the guardrail's judge-unavailable fallback for a run.

    Controls what happens when the guardrail JUDGE itself can't produce a verdict
    (http 0 / timeout / parse-fail / exception — verdict === null):
      - "escalate" (default, fail-safe): hold the command for operator review.
      - "allow": execute the command instead of stalling on judge downtime.
    Written to /outputs/<run_id>/guardrail/judge_fail.txt and read fresh every
    command by the guardrail, so a console flip takes effect on the agent's next
    bash call — no host recreate. Applies ONLY to the judge-unreachable case; a
    genuine refuse/escalate verdict is never overridden.
    """
    _valid_token(run_id, "run_id")
    value = (req.value or "").strip().lower()
    if value not in ("allow", "escalate"):
        raise HTTPException(status_code=400, detail="value must be 'allow' or 'escalate'")
    # Recommendation #5: judge_fail=allow MUST NOT be permitted against an
    # external / production target. A judge outage (http-0 / empty body) on a
    # routable target must keep fail-safe (escalate, hold for operator) — never
    # auto-execute. The launch gate already forces escalate as the default, so
    # this toggle is the only path to introduce 'allow'; refuse it here.
    if value == "allow":
        meta = _read_run_meta(run_id)
        eng_id = (meta or {}).get("engagement_id")
        if _engagement_target_is_external(eng_id):
            raise HTTPException(
                status_code=409,
                detail=("judge_fail=allow is not permitted for an external/production "
                        "target (judge outage must stay fail-safe). Use 'escalate'."),
            )
    gdir = _guardrail_dir(run_id)
    gdir.mkdir(parents=True, exist_ok=True)
    (gdir / "judge_fail.txt").write_text(value, encoding="utf-8")
    # Mirror into the run manifest so the console reflects the current value.
    meta = _read_run_meta(run_id)
    if meta:
        meta["judge_fail"] = value
        try:
            _atomic_write(_run_meta_path(run_id), meta)
        except Exception:
            pass
    return {"run_id": run_id, "judge_fail": value}


# =============================================================================
# Per-phase orchestration
#
# When a launch carries a `phases` chain, the engagement runs ONE phase at a
# time: each phase gets its own coder56 opencode session on the same container
# (shared goal.txt/mode.txt => shared scope + criticality). A background
# phase-driver task polls the active session's message stream and declares the
# phase complete when the agent's turn has ended (no pending tool + an assistant
# summary + idle), then either auto-advances (auto_continue) or pauses for
# operator review (review_each). Empty `phases` => legacy single-shot (above).
# =============================================================================

PHASE_POLL_S = 2.0          # driver message-poll interval
PHASE_IDLE_S = 12.0         # turn must be stable this long before "complete"
PHASE_DONE_SENTINEL = "### PHASE DONE ###"   # agent-emitted fast-complete marker

# C1/C2/C3 — MANDATORY Phase-0 TARGET-VALIDATION + threat-model + enumeration /
# multi-principal obligations. This block is injected VERBATIM into BOTH
# _compile_lead_directive AND _compile_phase_directive (single source of truth so
# the two compilers can never drift). It is the contract the agent prompt, the
# memory-seed header (TARGET_IDENTITY|/THREAT_MODEL|), and the backend's
# objective-met/coverage signals all key off. PRESERVES assessment §5: objective-
# first, technique-agnostic (no per-class playbooks), read-only authz differential,
# honest negatives.
PHASE0_TARGET_VALIDATION_BLOCK = (
    "PHASE 0 — TARGET-VALIDATION + THREAT MODEL + ATTACK-SURFACE/MULTI-PRINCIPAL (MANDATORY):\n"
    "- TARGET-VALIDATION (C1): before any other action, fetch the target fingerprint's marker "
    "(marker_path, default GET /api/health) and confirm it carries marker_match / canary_hash. "
    "If the operator left it blank, choose one unauthenticated endpoint and capture it now. "
    "Write the shared-namespace identity line to memory (ONE line, grep prefix `TARGET_IDENTITY|`):\n"
    "    TARGET_IDENTITY|app=<expected_app>|marker=<METHOD marker_path>|match=<marker_match>|hash=<canary_hash or none>\n"
    "At the FIRST action of the first post-recon phase AND at each phase boundary, RE-CHECK it. On mismatch emit "
    "EXACTLY: `TARGET IDENTITY MISMATCH — possible app swap; halting` and STOP the run; do NOT transfer prior findings. "
    "(The token `TARGET IDENTITY MISMATCH` is load-bearing — the backend/lead detect it.)\n"
    "- THREAT MODEL (C2): build a Phase-0 threat model from recon — crown-jewel assets, sensitive-data classes, "
    "trust boundaries, data flows, attacker goals, and an ordered list of vuln-class hypotheses high->low "
    "(risk_priorities). Emit ONE shared-namespace line (grep prefix `THREAT_MODEL|`):\n"
    "    THREAT_MODEL|app=<expected_app>|jewels=<comma-sep>|sensitive_data=<comma-sep>|trust_boundaries=<comma-sep>|"
    "data_flows=<comma-sep>|attacker_goals=<comma-sep>|risk_priorities=<ordered high->low>|owasp_backstop=<comma-sep A01..A10>\n"
    "Drive the phase plan RISK-FIRST from risk_priorities (test the top hypothesis first); OWASP Top-10 is a coverage "
    "backstop, not the spine.\n"
    "- ATTACK-SURFACE ENUMERATION + MULTI-PRINCIPAL (C3): enumerate the surface as inventory items — one "
    "shared-namespace line per item (grep prefix `SURFACE_ITEM|`):\n"
    "    SURFACE_ITEM|method=<GET|POST|...>|path=<normalized path with :param>|params=<comma-sep>|role=<min role that reaches it>|"
    "object_id=<pattern or none>|state=<precondition state or none>|cwe=<hint class or none>\n"
    "and a pointer: `ATTACK_SURFACE|count=<N>|principals=<principal1;principal2>`. Provision at least 2 OWNED principals "
    "in different tenants/roles, one shared-namespace line each (grep prefix `PRINCIPAL|`):\n"
    "    PRINCIPAL|id=<P1>|tenant=<tenantA>|role=<roleX>|how_provisioned=<owned/seeded; never a non-owned account>|token_loc=<path or VOLATILE>\n"
    "RoE-supreme: provision principals ONLY by authenticating with pre-existing owned/seeded credentials — NEVER create "
    "new accounts when the RoE forbids data modification. A finding is CONFIRMED FOR IMPACT only when demonstrated across "
    ">=2 owned principals in different tenants/roles on the same object IDs (the object-level differential).\n"
)
PHASE_DEFAULT_MAX_S = 21600  # per-phase hard timeout before forcing review. Raised to 6h (was 3600) so healthy heavy phases (Soroban SDK/XDR/WAT parsing) and long engagements never trip it; the stall watchdog (resets on phase-complete/task-spawn) still kills a GENUINELY wedged run after 6h of zero progress — well under the old 12h hang. Dial down to re-tighten.

# How often _lead_driver snapshots the in-container opencode.db mid-run (the
# exit snapshot at driver-exit covers phase boundaries; this closes the gap where
# a mid-phase host recreate/crash would otherwise lose the transcript).
RUN_SNAPSHOT_CADENCE_S = 300

# CONSECUTIVE-FAIL CIRCUIT BREAKER: if this many guardrail verdicts IN A ROW are
# dead-judge (tokens.total==0 OR reason matches a no-verdict signature), the judge
# itself is unreachable, so every command escalates and the agent cannot make real
# progress. Reference run b1425481 = 88/88 dead-judge escalates, yet all 4 phases
# were marked 'completed'. Hard-pause instead of burning retries / faking success.
# Raised 3 -> 6: the nemotron proxy now retries intermittent upstream 404/500/5xx
# (nemotron_proxy._is_transient), so a single NVIDIA blip no longer produces a
# dead verdict. 6 gives margin against CLUSTERED blips while still halting on a
# genuinely-sustained judge outage (a dead verdict = 4 guardrail attempts x 4 proxy
# retries of failed calls, so 6 in a row is unambiguously a down judge, not noise).
GUARDRAIL_CIRCUIT_BREAKER_N = 6
# A verdict is 'dead-judge' when the JUDGE produced no usable output (vs a genuine
# refuse/escalate the judge deliberately returned). tokens.total==0 = judge call
# returned empty body (http 0 / connection fail / parse fail); these reason
# substrings are the guardrail's own empty-output markers. A real escalate that
# cost tokens is NOT matched here (that path is the undecided-escalate gate below).
_RE_DEAD_JUDGE_REASON = re.compile(
    r"(no assistant text|http 0|no verdict|produced no assistant|empty body|"
    r"judge.{0,12}unreachable|judge.{0,12}failed|parse fail|no response)",
    re.IGNORECASE,
)


def _default_threatmodel_phases(directive: str) -> List[PhaseSpec]:
    """Threat-model-driven default plan for an engagement launched with NO drafted
    phases (the objective-launch path). Without this, an empty `phases` list makes
    accept_initial_directive fall through to legacy single-shot: the raw directive
    goes to the generic coder56 agent, so no coder56_lead / Phase 0 / _lead_driver /
    snapshot runs and the engagement never finalizes (the OpenHospital run hit
    exactly this — `current_phase` stayed -1, no THREAT_MODEL|, status frozen at
    `planning`).

    Synthesizing this skeleton routes every launch through coder56_lead + Phase 0 +
    _lead_driver + finalization — mirroring run_planned_run's checklist fallback
    (coder56.py:3340) so the methodology restructure applies to objective-launches
    too. The lead generates the risk-first ordering from the threat model Phase 0
    produces; OWASP Top-10 is a coverage backstop, not the spine (assessment §4,
    Option A). Objectives stay objective-first / technique-agnostic (no per-class
    playbooks — preserve §5) and carry the load-bearing marker strings the deployed
    agents already emit/read (TARGET_IDENTITY|/THREAT_MODEL|/SURFACE_ITEM|/PRINCIPAL|
    /TESTED|)."""
    return [
        PhaseSpec(
            objective=(
                "Phase 0 — THREAT MODEL + TARGET-VALIDATION. From recon (no exploitation yet), "
                "capture + re-check the target identity and build the threat model: crown-jewel "
                "assets, sensitive-data classes, trust boundaries, data flows, attacker goals, and "
                "an ordered list of vuln-class hypotheses high->low (risk_priorities). Emit the "
                "shared-namespace lines `TARGET_IDENTITY|app=…|marker=…|match=…|hash=…` and "
                "`THREAT_MODEL|app=…|jewels=…|sensitive_data=…|trust_boundaries=…|data_flows=…|"
                "attacker_goals=…|risk_priorities=…|owasp_backstop=…` to engagement memory. On a "
                "target-identity mismatch emit `TARGET IDENTITY MISMATCH` and STOP."
            ),
            tactic_id="TA0043", technique_ids=[], note="Phase 0 threat model + target identity",
            tools=[], checklist=[],
        ),
        PhaseSpec(
            objective=(
                "Phase 1 — ATTACK-SURFACE ENUMERATION + MULTI-PRINCIPAL HARNESS. Enumerate the full "
                "surface as inventory items — one `SURFACE_ITEM|method=…|path=…|params=…|role=…|"
                "object_id=…|state=…|cwe=…` line per endpoint/param/role/object-id, plus an "
                "`ATTACK_SURFACE|count=…|principals=…` pointer. Provision >=2 OWNED principals in "
                "different roles (owned/seeded creds only; RoE-supreme — never create accounts), one "
                "`PRINCIPAL|id=…|tenant=…|role=…|how_provisioned=…|token_loc=…` each. This inventory "
                "is the substrate later phases test against and the reporter's coverage matrix consumes."
            ),
            tactic_id="TA0043", technique_ids=[], note="Attack-surface inventory + principals",
            tools=[], checklist=[],
        ),
        PhaseSpec(
            objective=(
                "Phase 2 — RISK-FIRST TESTING + VERIFY (against the threat model + inventory). Test "
                "risk_priorities[0] first, then fan out: for each candidate finding, delegate "
                "coder56_verifier for an independent read-only reproduction and abide by its verdict "
                "(CONFIRMED / NOT_A_VULN / INCONCLUSIVE / NOT_CONFIRMABLE). On each CONFIRMED finding, "
                "run the finding-driven re-plan — enumerate sibling endpoints/params of the same class, "
                "attempt chains, same-DTO fan-out. Append one `TESTED|method=…|path=…|…|status=…` record "
                "per surface element exercised (tested_confirmed/tested_negative/could_not_test)."
            ),
            tactic_id="TA0043", technique_ids=[], note="Risk-first testing + verification",
            tools=[], checklist=[],
        ),
        PhaseSpec(
            objective=(
                "Phase 3 — SYNTHESIZE COVERAGE + ENGAGEMENT SUMMARY. Confirm coverage BY SURFACE ITEM "
                "(tested vs untested, grouped by threat-model crown jewel), frame confirmed findings as "
                "attack paths with business impact (not an isolated CVE list), surface any "
                "could_not_test/NOT_CONFIRMABLE items honestly, and write the engagement summary. Emit "
                "`CATEGORY OBJECTIVE MET (<owasp_id>) — <evidence>` for any category whose objective is met."
            ),
            tactic_id="TA0043", technique_ids=[], note="Coverage synthesis + summary",
            tools=[], checklist=[],
        ),
    ]


def _ensure_research_phase_if_needed(obj: Dict[str, Any], target: str,
                                     rules_of_engagement: str) -> Dict[str, Any]:
    """Prepend a recon-first Phase R (is_research_phase=True) when the OpenAPI/
    Swagger spec, the role set, or the tech stack is NOT explicitly stated in the
    drafted plan. Phase R resolves exactly the unknowns that, unresolved, recreate
    the de1e6112 re-recon loop, and PERSISTS them so every later phase reads them
    as ground truth (the prior_findings block elevates a research phase's output to
    authoritative fact in _compile_phase_directive). No-op (returns obj unchanged)
    if a research phase is already present or all three unknowns are stated.

    Idempotent and additive: never removes or reorders drafted phases."""
    if not isinstance(obj, dict):
        return obj
    phases = obj.get("phases")
    if not isinstance(phases, list):
        phases = []
        obj["phases"] = phases

    def _field(p: Any, name: str, default: Any = "") -> Any:
        """Read a field from a dict OR a pydantic PhaseSpec (the drafted plan and
        the API/WEBAPP skeletons hold different shapes)."""
        if isinstance(p, dict):
            return p.get(name, default)
        return getattr(p, name, default)

    # Already has a research phase => nothing to do (idempotent across re-drafts).
    for p in phases:
        if _field(p, "is_research_phase", False):
            return obj
    blob = " ".join(str(x or "") for x in (obj.get("objective", ""), obj.get("target", ""),
                                           target, rules_of_engagement,
                                           obj.get("rules_of_engagement", ""))).lower()
    phases_blob = " ".join(str(_field(p, "objective", "")) + " " + str(_field(p, "note", ""))
                           for p in phases).lower()
    blob = f"{blob} {phases_blob}"
    has_spec = bool(re.search(r"swagger|openapi|spec\b|/v[0-9]+/api-docs|springdoc", blob))
    has_roles = bool(re.search(r"\b(role|principal|tenant|admin|chief|doctor|nurse|user)[ s]*(set|list|group|=)",
                               blob)) or bool(re.search(r"PRINCIPAL\||role\s*[:=]\s*\w", blob))
    has_stack = bool(re.search(r"spring|tomcat|maria\s*db|postgres|node|express|django|flask|nginx|apache|java\b|\bjdk",
                               blob))
    if has_spec and has_roles and has_stack:
        return obj  # nothing unknown to resolve
    phase_r = PhaseSpec(
        objective=(
            "Phase R — RESEARCH/RECON FIRST (before any testing). Determine and PERSIST as ground "
            "truth: is this an API? locate + harvest the OpenAPI/Swagger spec; enumerate the tech "
            "stack (framework, DB, server versions); enumerate EVERY role and provision >=2 OWNED "
            "principals in DIFFERENT role groups (seeded creds only; RoE-supreme — never create "
            "accounts). Write each fact to /outputs/$RUN_ID/memory/MEMORY.md: TARGET_IDENTITY|, "
            "OPENAPI_SPEC|path=…|endpoint_count=…, TECH_STACK|…, and one "
            "PRINCIPAL|id=…|group=…|role=…|token_loc=<FILE path>| per group. Do NOT exploit. "
            "End with ### PHASE DONE ###."
        ),
        tactic_id="TA0043", technique_ids=[], note="Phase R recon-first research (ground truth)",
        tools=[], checklist=[],
        is_research_phase=True,
    )
    obj["phases"] = [phase_r] + list(phases)
    return obj


def _default_api_phases(directive: str) -> List[PhaseSpec]:
    """Mode-selected skeleton for EngagementMode.API: Phase R (recon-first ground
    truth) + one PhaseSpec per OWASP API Security Top-10 (2023) category API1..API9
    (API10 is unsafe-consumption / white-box-only and is folded into Phase Z),
    ordered RISK-FIRST so the integrity classes lead, + a coverage-synthesis Phase Z
    that mandates a WSTG-structured summary. Every write-category phase mandates
    cross-role PUT/DELETE/PATCH (the de1e6112 zero-write-coverage gap)."""
    # Risk-first order: BOLA, BFLA, mass-assignment, business-logic lead (the
    # integrity questions on a clinical/EHR target), then auth, consumption, SSRF,
    # misconfig, inventory.
    risk_order = ["API1", "API5", "API3", "API6", "API2", "API4", "API7", "API8", "API9"]
    by_id = {c["id"]: c for c in api_security_catalog()["categories"]}
    phases: List[PhaseSpec] = [
        PhaseSpec(
            objective=(
                "Phase R — RESEARCH/RECON FIRST (before any testing). Determine and PERSIST as ground "
                "truth: is this an API? locate + harvest the OpenAPI/Swagger spec; enumerate the tech "
                "stack (framework, DB, server versions); enumerate EVERY role and provision >=2 OWNED "
                "principals in DIFFERENT role groups (seeded creds only; RoE-supreme — never create "
                "accounts). Write each fact to /outputs/$RUN_ID/memory/MEMORY.md: TARGET_IDENTITY|, "
                "OPENAPI_SPEC|path=…|endpoint_count=…, TECH_STACK|…, and one "
                "PRINCIPAL|id=…|group=…|role=…|token_loc=<FILE path>| per group. Do NOT exploit. "
                "End with ### PHASE DONE ###."
            ),
            tactic_id="TA0043", technique_ids=[], note="Phase R recon-first research (ground truth)",
            tools=[], checklist=[],
            is_research_phase=True,
        )
    ]
    write_methods = ("PUT", "PATCH", "DELETE")
    for cid in risk_order:
        cat = by_id.get(cid)
        if not cat:
            continue
        tmpl = cat.get("objective_template", "") or ""
        checklist = list(cat.get("checklist", []))
        # Every write-category phase MUST mandate cross-role PUT/DELETE/PATCH (the
        # de1e6112 gap: zero cross-role writes were ever sent).
        checklist.append(
            "Cross-role WRITE matrix: for every state-changing verb in this category "
            f"({', '.join(write_methods)}), send it from >=2 owned principals in DISTINCT role "
            "groups and capture the authorization differential (who can create/alter/delete what)."
        )
        phases.append(PhaseSpec(
            objective=tmpl,
            tactic_id="TA0043", technique_ids=[],
            note=f"{cid} {cat.get('name', '')}",
            tools=list(cat.get("tools", [])),
            checklist=checklist,
            api_category=cid,
        ))
    phases.append(PhaseSpec(
        objective=(
            "Phase Z — SYNTHESIZE COVERAGE + WSTG-STRUCTURED SUMMARY. Confirm coverage BY SURFACE "
            "ITEM and BY API category (API1-API9 tested vs untested), frame confirmed findings as "
            "attack paths with business impact, surface any could_not_test / NOT_CONFIRMABLE items "
            "honestly, and write the engagement summary. For any API category whose objective is met, "
            "emit `CATEGORY OBJECTIVE MET (<api_id>) — <evidence>`. Explicitly note API10 (unsafe "
            "consumption of third-party APIs) as a white-box follow-up if not observable."
        ),
        tactic_id="TA0043", technique_ids=[], note="Coverage synthesis + WSTG summary",
        tools=[], checklist=[],
    ))
    return phases


def _default_webapp_phases(directive: str) -> List[PhaseSpec]:
    """Mode-selected skeleton for EngagementMode.WEBAPP: Phase R (recon-first ground
    truth) + one PhaseSpec per OWASP Top-10 (2021) category A01..A10, ordered
    RISK-FIRST, + a coverage-synthesis Phase Z that mandates a WSTG-structured
    summary. Mirrors _default_api_phases on the web-app catalog."""
    # Risk-first order: Broken Access Control, Injection, Auth failures lead.
    risk_order = ["A01", "A03", "A07", "A04", "A05", "A10", "A02", "A06", "A08", "A09"]
    by_id = {c["id"]: c for c in owasp_catalog()["categories"]}
    phases: List[PhaseSpec] = [
        PhaseSpec(
            objective=(
                "Phase R — RESEARCH/RECON FIRST (before any testing). Determine and PERSIST as ground "
                "truth: enumerate the attack surface (endpoints, parameters, roles); enumerate the tech "
                "stack (framework, server versions); enumerate EVERY role and provision >=2 OWNED "
                "principals in DIFFERENT role groups (seeded creds only; RoE-supreme — never create "
                "accounts). Write each fact to /outputs/$RUN_ID/memory/MEMORY.md: TARGET_IDENTITY|, "
                "TECH_STACK|…, and one PRINCIPAL|id=…|group=…|role=…|token_loc=<FILE path>| per group. "
                "Do NOT exploit. End with ### PHASE DONE ###."
            ),
            tactic_id="TA0043", technique_ids=[], note="Phase R recon-first research (ground truth)",
            tools=[], checklist=[],
            is_research_phase=True,
        )
    ]
    write_methods = ("POST", "PUT", "PATCH", "DELETE")
    for cid in risk_order:
        cat = by_id.get(cid)
        if not cat:
            continue
        tmpl = cat.get("objective_template", "") or ""
        checklist = list(cat.get("checklist", []))
        checklist.append(
            "Cross-role WRITE matrix: for every state-changing verb "
            f"({', '.join(write_methods)}), send it from >=2 owned principals in DISTINCT role "
            "groups and capture the authorization differential."
        )
        phases.append(PhaseSpec(
            objective=tmpl,
            tactic_id="TA0043", technique_ids=[],
            note=f"{cid} {cat.get('name', '')}",
            tools=list(cat.get("tools", [])),
            checklist=checklist,
            api_category=cid,
        ))
    phases.append(PhaseSpec(
        objective=(
            "Phase Z — SYNTHESIZE COVERAGE + WSTG-STRUCTURED SUMMARY. Confirm coverage BY SURFACE "
            "ITEM and BY OWASP category (A01-A10 tested vs untested), frame confirmed findings as "
            "attack paths with business impact, surface any could_not_test / NOT_CONFIRMABLE items "
            "honestly, and write the engagement summary. For any category whose objective is met, "
            "emit `CATEGORY OBJECTIVE MET (<owasp_id>) — <evidence>`."
        ),
        tactic_id="TA0043", technique_ids=[], note="Coverage synthesis + WSTG summary",
        tools=[], checklist=[],
    ))
    return phases


# Live driver tasks, keyed by run_id. One driver per run; idempotent arming.
_phase_drivers: Dict[str, "asyncio.Task"] = {}


PHASE_SUMMARY_CAP = 3500   # max chars forwarded per phase (bounds context growth)


def _parse_tool_command(state_input: Any) -> str:
    """opencode stores a tool call's arguments as the repr of a python dict in
    part.state.input, e.g. \"{'command': 'nmap -p 80 10.0.0.1'}\". Return a short
    human label for what the tool was asked to do. For payload-bearing tools
    (write/edit) we surface the identifying key (file_path/path) and never dump
    large bodies (content/diff/patch) into the digest."""
    if isinstance(state_input, dict):
        # identifying keys: small values that describe WHAT was done
        for key in ("command", "cmd", "path", "file_path", "file", "url", "query", "pattern"):
            val = state_input.get(key)
            if val:
                return str(val)
        # payload keys: large bodies — summarize, never forward wholesale
        for key in ("content", "diff", "patch", "file_text", "new_string", "old_string", "text"):
            body = state_input.get(key)
            if body:
                body = str(body)
                return f"{key} ({len(body)} chars) …{body[-60:]}"
        # generic fallback: keep small values, summarize large ones
        parts = []
        for k, v in state_input.items():
            sv = str(v)
            if len(sv) > 80:
                sv = f"{len(sv)} chars"
            parts.append(f"{k}={sv}")
        return ", ".join(parts) or str(state_input)
    if isinstance(state_input, str) and state_input.strip():
        s = state_input.strip()
        try:
            parsed = ast.literal_eval(s)
            if isinstance(parsed, dict):
                return _parse_tool_command(parsed)
        except Exception:
            pass
        return s
    return ""


def _summarize_messages(msgs: List[Dict[str, Any]], cap: int = PHASE_SUMMARY_CAP) -> str:
    """Reconstruct a bounded 'what this phase did and found' digest from a
    session's message stream: the agent's own text turns plus each tool command
    and a short excerpt of its output.

    This is the robust source of phase context. glm-5.2 frequently skips the tidy
    'PHASE SUMMARY + sentinel' the directive asks for, so the agent's captured
    final text is often empty — but the actual findings (the nmap that proved the
    host up, the curl that listed /admin and /backup, the 404s) live in the tool
    I/O. We recover them here so later phases inherit real ground truth instead
    of starting blind."""
    if not msgs:
        return ""
    lines: List[str] = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        parts = m.get("parts") or []
        for p in parts:
            if not isinstance(p, dict):
                continue
            ptype = p.get("type")
            if ptype == "text":
                txt = (p.get("text") or "").strip()
                # skip the raw directive echo (the phase prompt itself); strip a
                # stray sentinel so it can't be echoed back and falsely trip the
                # next phase's completion detector.
                if txt and not txt.startswith("=== AUTHORIZED ENGAGEMENT"):
                    txt = txt.replace(PHASE_DONE_SENTINEL, "[/done-marker/]")
                    lines.append(f"[agent] {txt}")
            elif ptype == "tool":
                tool = (p.get("tool") or "tool").strip() or "tool"
                st = p.get("state") or {}
                cmd = _parse_tool_command(st.get("input"))
                out = (st.get("output") or "").strip()
                # Keep BOTH ends: HTTP headers / page bodies bury the findings up
                # front, while nmap & friends put their summary at the end. A
                # tail-only excerpt would drop the ACME portal / /admin / /backup
                # text that lives at the head of a curl body.
                if len(out) > 320:
                    out = out[:180].rstrip() + " …[middle truncated]… " + out[-120:].lstrip()
                out = out.replace(PHASE_DONE_SENTINEL, "[/done-marker/]")
                head = f"$ {tool}"
                if cmd:
                    head += f": {cmd}"
                lines.append(head)
                if out:
                    lines.append("    > " + out.replace("\n", " / "))
        if sum(len(l) for l in lines) > cap:
            break
    digest = "\n".join(lines).strip()
    if len(digest) > cap:
        # Keep both ends: the head carries early recon (headers / landing page)
        # and the tail carries the most recent finding — a head-only truncate
        # would drop the latter, which is often the load-bearing result. `keep`
        # leaves room for the middle-truncation marker so len stays <= cap.
        keep = cap - 30
        head = digest[: keep // 2]
        tail = digest[-(keep - len(head)):] if keep - len(head) > 0 else ""
        digest = head.rstrip() + "\n…[middle truncated]…\n" + tail.lstrip()
    return digest


def _extract_phase_summary(final_text: str) -> str:
    """Clean a phase's captured final assistant text for forwarding: drop the
    completion sentinel and, if the agent used a header-shaped 'PHASE SUMMARY'
    marker (markdown header or line start), keep only that section. Matching only
    header-shaped occurrences avoids discarding real findings the agent wrote as
    prose before an incidental 'phase summary' mention."""
    if not final_text:
        return ""
    text = final_text.replace(PHASE_DONE_SENTINEL, "").strip()
    m = re.search(r"(?im)^[#>\*\-]*\s*PHASE SUMMARY\b", text)
    if m:
        text = text[m.start():].strip()
    return text.strip()


# A captured final_text below this length is almost certainly a mid-thought
# fragment ('Let me check ...', 'Now let me test ...'), not a phase conclusion.
# A directive-compliant 'PHASE SUMMARY' wrap-up (or any real multi-finding
# conclusion) is far longer; ~3h of work reduced to a 57-char sentence is the
# failure mode this threshold blocks.
_SUMMARY_MIN_CHARS = 240


def _is_substantive_summary(text: str) -> bool:
    """True only when a phase's captured final_text is a genuine conclusion worth
    forwarding as-is — NOT a stray mid-thought planning fragment. When False, the
    caller falls through to the reconstructed tool-I/O digest (_summarize_messages),
    because the findings then live in the commands the agent ran.

    Substantive when ANY of: completion sentinel present; a 'PHASE SUMMARY' header;
    long enough that it cannot be a one-line 'let me ...' fragment; or >= 2
    non-trivial lines (a multi-point wrap-up)."""
    if not text:
        return False
    if PHASE_DONE_SENTINEL in text:
        return True
    if re.search(r"(?im)^[#>\*\-]*\s*PHASE SUMMARY\b", text):
        return True
    if len(text) >= _SUMMARY_MIN_CHARS:
        return True
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) >= 2:
        return True
    return False


def _resolve_run_paths(text: str, run_id: str) -> str:
    """Replace the literal `$RUN_ID` token with the real run id everywhere it
    appears in agent-facing text. Without this, the agent expands `$RUN_ID` in
    its own shell — where RUN_ID may be unset or the legacy fixed sandbox value —
    producing a LITERAL `/outputs/$RUN_ID/` dir that persists across runs and is
    pre-filled with OTHER engagements' findings (cross-engagement contamination;
    observed on run de1e6112). Resolving server-side means the agent always sees
    the real path and can never create/read the literal dir. No-op when run_id is
    falsy so callers can apply it unconditionally."""
    if not text or not run_id:
        return text or ""
    return text.replace("$RUN_ID", run_id)


# A3: phase numbers are DERIVED from the array index at render time, never stored
# in the objective text. This strips a leading "Phase N —" / "=== PHASE N: ==="
# label so a duplicated Phase-0 objective can't shift every later label by one
# (the de1e6112 off-by-one: index 8 carried the "PHASE 7" label => frontend "9").
_RE_PHASE_LABEL_PREFIX = re.compile(r"^\s*=*\s*PHASE\s+\d+\s*[:\-–—]\s*", re.IGNORECASE)


def _strip_phase_label(text: str) -> str:
    """Remove a leading phase-number label so the displayed number is always the
    array index (index+1). No-op on objectives that don't start with one."""
    if not text:
        return text or ""
    return _RE_PHASE_LABEL_PREFIX.sub("", text.lstrip()).strip()


def _phase_objective_key(spec: Any) -> str:
    """Normalized objective for duplicate detection (label-stripped + casefolded)."""
    if isinstance(spec, dict):
        obj = spec.get("objective") or ""
    else:
        obj = getattr(spec, "objective", "") or ""
    return _strip_phase_label(str(obj)).casefold()


def _dedup_phase_plan(phases: List[Any]) -> List[Any]:
    """A4: drop a phase whose normalized objective duplicates the immediately
    preceding phase's (the dup-Phase-0 failure mode). Non-adjacent repeats (a
    legit re-test) are preserved. Later phases render by index, so removing one
    does not desync numbering."""
    if not phases:
        return phases
    out: List[Any] = []
    for p in phases:
        key = _phase_objective_key(p)
        if key and out and key == _phase_objective_key(out[-1]):
            logger.warning("phase plan: dropping consecutive duplicate objective (%.60s)", key)
            continue
        out.append(p)
    return out


# A1: ATT&CK tactics that REQUIRE a host/OS foothold and have no web-app analogue.
# When the engagement grants only application-level access (HTTP + seeded app
# credentials, no SSH/RDP/host shell), these phases find nothing and burn the run
# (de1e6112: privesc + host-credential-extraction + exfil-sim produced nothing and
# looped for ~44h). Discovery/Persistence/Evasion/Collection are KEPT — they have
# web forms (endpoint/role enumeration, account backdoor, bulk-data export).
_HOST_COMPROMISE_TACTICS = {"TA0004", "TA0006", "TA0008", "TA0010", "TA0011"}


def _infer_target_class(target: str, rules_of_engagement: str) -> str:
    """Coarse target class from scope + RoE text: 'web' (HTTP/S app/API, no host
    shell), 'host' (SSH/RDP/SMB/AD/host-OS creds), or 'mixed'."""
    blob = f"{target or ''} {rules_of_engagement or ''}".lower()
    has_web = bool(re.search(r"https?://|api|rest|web ?app|swagger|endpoint|/auth|jwt|bearer|login", blob))
    has_host = bool(re.search(r"\bssh\b|\brdp\b|\bsmb\b|active directory|\bkerberos\b|/etc/|root@|host shell|os credent", blob))
    if has_host and has_web:
        return "mixed"
    if has_host:
        return "host"
    return "web"  # default — these ranges are overwhelmingly web/API


def _filter_phases_for_target(phases: List[Any], target_class: str) -> List[Any]:
    """A1: drop host-compromise-only phases when the target grants no host access.
    Never empties the plan (falls back to the original list). Idempotent."""
    if target_class == "host" or not phases:
        return phases
    kept: List[Any] = []
    for p in phases:
        tac = ((p.get("tactic_id") if isinstance(p, dict) else getattr(p, "tactic_id", "")) or "")
        if tac.upper() in _HOST_COMPROMISE_TACTICS:
            logger.info("applicability filter (%s target): dropping %s phase", target_class, tac.upper())
            continue
        kept.append(p)
    return kept or list(phases)


def _compile_phase_directive(full_directive: str, phase_index: int, total: int,
                             objective: str, prior_findings: Optional[List[str]] = None,
                             pf_is_research: Optional[List[bool]] = None) -> str:
    """Build the prompt for a single phase. The FULL engagement directive is
    included as the authorized-scope context (it is also the guardrail's
    goal.txt), and the phase objective is layered on top. When `prior_findings`
    is supplied (one entry per earlier phase, in phase order, '' for phases that
    produced nothing), the accumulated results of completed phases are injected so
    this phase builds on established facts instead of re-discovering them. The
    agent is told to work ONLY this phase and to end with a sentinel marker the
    driver watches. Earlier phase prose is copied into later phase prompts as an
    explicit handoff; shared engagement memory remains the authoritative durable
    record and parallel-work bus.

    When `pf_is_research` marks an earlier phase as a research phase (Phase R),
    that phase's persisted output is elevated to AUTHORITATIVE GROUND TRUTH in the
    header — later phases read the spec/roles/stack it persisted as fact and must
    NOT re-enumerate, re-probe, or re-fingerprint them (kills the de1e6112 re-recon
    loop)."""
    research_header = ""
    if prior_findings and pf_is_research and any(pf_is_research):
        research_header = (
            " PHASE R (RESEARCH) OUTPUT IS GROUND TRUTH: the OpenAPI spec location, "
            "endpoint inventory, tech stack, and role set an earlier Phase R persisted to "
            "/outputs/$RUN_ID/memory/MEMORY.md are authoritative. Read them first; derive "
            "KNOWN/GAPS/DELTA; do NOT re-enumerate the spec, re-probe roles, or re-fingerprint "
            "the stack."
        )
    prior_block = ""
    if prior_findings:
        chunks = []
        for i, finding in enumerate(prior_findings):
            finding = (finding or "").strip()
            if finding:
                chunks.append(f"--- PHASE {i + 1} findings ---\n{finding}")
        if chunks:
            prior_block = (
                "\nPRIOR PHASE FINDINGS (accumulated results reported by earlier phases of "
                "THIS engagement — these are established facts; rely on them and do NOT "
                "repeat the work that produced them). They complement the authoritative "
                "shared memory at /outputs/$RUN_ID/memory/MEMORY.md:\n\n"
                + "\n\n".join(chunks) + "\n\n"
            )
    return (
        "=== AUTHORIZED ENGAGEMENT (sanctioned cyber-range exercise) ===\n"
        f"You are executing PHASE {phase_index + 1} of {total} of the engagement below.\n\n"
        "FULL ENGAGEMENT DIRECTIVE (your authorized scope — stay strictly within it):\n"
        f"{full_directive.strip()}\n\n"
        f"{PHASE0_TARGET_VALIDATION_BLOCK}\n"
        f"{research_header}"
        f"{prior_block}"
        "THIS PHASE'S OBJECTIVE:\n"
        f"{objective.strip()}\n\n"
        "MEMORY-FIRST EXECUTION CONTRACT:\n"
        "1. Before any other action, read /outputs/$RUN_ID/memory/MEMORY.md.\n"
        "2. Trust established facts, negative results, artifacts, and verifier-confirmed "
        "fingerprints. Derive KNOWN / GAPS / DELTA and execute only DELTA.\n"
        "3. Do not repeat recon, route/role/session baselines, failed tests, tool installs, "
        "or a verified fingerprint. Re-run only for an explicit operator request, direct "
        "contradiction, or a volatile prerequisite; append RERUN_REASON.\n"
        "4. Memory is the live parallel-work bus. Before a substantial branch, reread its "
        "tail and use [CLAIMED] WORK_ID / [DONE] WORK_ID. Append any information useful to "
        "another pentest phase immediately, not only at phase end.\n"
        "5. PERSIST YOUR OUTPUT (every phase, before PHASE DONE): append one "
        "`TESTED|method=...|path=...|params=...|role=...|object_id=...|status=...|evidence=...` "
        "line to /outputs/$RUN_ID/memory/MEMORY.md for each endpoint x param x role x object-id "
        "you actually exercised (status = tested_confirmed | tested_negative | not_applicable | "
        "could_not_test | unverifiable) — this drives the coverage matrix, so a phase that "
        "exercises endpoints but writes no TESTED| line reads as uncovered. Also append a short "
        "dated entry for any confirmed/unverified finding (route, vuln class, verified status, "
        "evidence path). APPEND ONLY (>>); never edit prior lines.\n\n"
        "Work ONLY this phase's objective within the authorized scope above. Do not begin "
        "any later phase. When this phase's objective is met (or you cannot progress), write "
        "a concise PHASE SUMMARY of what you found / achieved, then end your message with "
        "this exact marker on its own line:\n"
        f"{PHASE_DONE_SENTINEL}\n"
        "=== END ==="
    )


def _detect_turn_complete(msgs: List[Dict[str, Any]]) -> tuple:
    """Inspect a session's message list for turn-end signals.

    Returns (pending_tool, final_text, activity):
      pending_tool - a tool part is still awaiting completion (guardrail/approval)
                     => the turn is NOT done (distinguishes a pause from a finish)
      final_text   - text of the most recent assistant message that has text
      activity     - the agent has produced at least one assistant msg or tool call
                     (guards against declaring an idle no-op "complete")
    """
    pending_tool = False
    final_text = ""
    activity = False
    for m in msgs or []:
        info = m.get("info") or {}
        role = info.get("role") or m.get("role") or m.get("type")
        parts = m.get("parts") or []
        for p in parts:
            if not isinstance(p, dict):
                continue
            if p.get("type") == "tool":
                activity = True
                st = (p.get("state") or {}).get("status")
                if st and st not in ("completed", "error"):
                    pending_tool = True
        if role == "assistant":
            activity = True
            for p in parts:
                if isinstance(p, dict) and p.get("type") == "text" and (p.get("text") or "").strip():
                    final_text = p.get("text")
    return pending_tool, final_text, activity


async def _start_phase(run_id: str, index: int, addr: str, revised_objective: Optional[str] = None) -> str:
    """Create a fresh coder56 session for `index`, send its phase directive, mark
    it RUNNING, persist, and return the session id. Idempotent: a phase already
    RUNNING with a session is not restarted. A phase that was awaiting_review is
    re-run (the 'review & correct' path)."""
    meta = _read_run_meta(run_id)
    phases = meta.get("phases") or []
    rt = meta.get("phase_runtime") or []
    if not (0 <= index < len(phases)) or index >= len(rt):
        raise HTTPException(status_code=409, detail=f"Phase index {index} out of range")
    entry = rt[index]
    if entry.get("status") == PhaseStatus.RUNNING.value and entry.get("session_id"):
        return entry["session_id"]

    spec = phases[index]
    objective = _strip_phase_label(
        (revised_objective or spec.get("objective") or "").strip()
        or f"Execute phase {index + 1} of the authorized engagement (see full directive)."
    )
    # Carry each earlier phase's captured result forward as context. Index-aligned
    # (incl. '' for phases that produced nothing) so the 'PHASE N findings' labels
    # in the prompt match the real phase numbers; junk fallbacks are blanked so we
    # never forward placeholder noise like '(no summary emitted ...)'.
    # pf_is_research is read per-phase from the manifest's is_research_phase flag
    # so _compile_phase_directive can elevate a Phase R's persisted output to
    # authoritative ground truth in the prompt header.
    _JUNK_RESULT_PREFIXES = ("(no summary emitted", "(no activity captured",
                             "(phase timed out", "[phase timed out")
    prior_findings: List[str] = []
    pf_is_research: List[bool] = []
    for i in range(index):
        if i < len(rt):
            r = (rt[i].get("result") or "").strip()
            prior_findings.append("" if r.startswith(_JUNK_RESULT_PREFIXES) else r)
        else:
            prior_findings.append("")
        _spec_i = phases[i] if i < len(phases) else {}
        pf_is_research.append(bool(_spec_i.get("is_research_phase")) if isinstance(_spec_i, dict) else False)
    prompt = _compile_phase_directive(
        meta.get("directive") or "", index, len(phases), objective,
        prior_findings=prior_findings or None,
        pf_is_research=pf_is_research or None,
    )
    prompt = _resolve_run_paths(prompt, run_id)

    from ..services.opencode_client import create_session_async, send_prompt_async
    cres = await create_session_async(host=addr, port=4096, title=f"Phase {index + 1}: {objective[:40]}")
    if not cres.get("success") or not cres.get("session_id"):
        raise HTTPException(status_code=502, detail=f"Failed to create phase session: {cres.get('error')}")
    session_id = cres["session_id"]
    sres = await send_prompt_async(
        session_id=session_id, prompt=prompt, host=addr, port=4096,
        agent=AgentType.CODER56.value, async_mode=True, timeout=30,
    )
    if not sres.get("success"):
        raise HTTPException(status_code=502, detail=f"Failed to send phase prompt: {sres.get('error')}")

    rt[index] = {
        "index": index,
        "status": PhaseStatus.RUNNING.value,
        "objective": objective,
        "tactic_id": spec.get("tactic_id", ""),
        "technique_ids": list(spec.get("technique_ids") or []),
        "session_id": session_id,
        "result": "",
        "started_at": _now_iso(),
        "completed_at": "",
    }
    meta["phase_runtime"] = rt
    meta["current_phase"] = index
    _atomic_write(_run_meta_path(run_id), meta)
    return session_id


# Legacy single-shot runs (no phases, orchestration != native_subagents) have
# no driver watching the coder56 session, so the ephemeral opencode.db would
# never be snapshotted on their completion. A one-shot finalizer per legacy run
# waits for the session turn to go idle (or a deadline) then snapshots once.
_legacy_finalizers: Dict[str, asyncio.Task] = {}


def _arm_legacy_finalizer(run_id: str) -> None:
    """Best-effort: spawn (once) a watcher that snapshots the legacy single-shot
    run's opencode.db when its coder56 session turn ends. Never raises."""
    try:
        existing = _legacy_finalizers.get(run_id)
        if existing and not existing.done():
            return
        _legacy_finalizers[run_id] = asyncio.create_task(_legacy_finalizer(run_id))
    except Exception as exc:
        logger.warning("legacy_finalizer[%s] arm failed: %s", run_id, exc)


async def _legacy_finalizer(run_id: str) -> None:
    """Watch a legacy single-shot coder56 session; snapshot its opencode.db once
    the turn is idle (no pending tool) or after LEGACY_FINALIZER_DEADLINE_S,
    whichever comes first. Mirrors _lead_driver's completion heuristic in miniature."""
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import get_session_messages_async
    deadline = time.monotonic() + 21600  # 6h whole-run backstop (PHASE_DEFAULT_MAX_S ceiling)
    last_activity = time.monotonic()
    try:
        while time.monotonic() < deadline:
            await asyncio.sleep(PHASE_POLL_S * 2)
            meta = _read_run_meta(run_id)
            session_id = str(meta.get("session_id") or "")
            if not session_id:
                break
            container_id = meta.get("container_id", "")
            if not container_id:
                break
            try:
                addr = await get_container_address(container_id)
            except Exception:
                continue
            res = await get_session_messages_async(session_id=session_id, host=addr, port=4096)
            if not res.get("success"):
                continue
            msgs = res.get("messages", []) or []
            pending_tool = False
            for m in msgs:
                for p in (m.get("parts") or []):
                    if isinstance(p, dict) and p.get("type") == "tool":
                        st = p.get("state") or {}
                        if st.get("status") and st.get("status") not in ("completed", "error"):
                            pending_tool = True
            # Turn complete = has messages and nothing pending. Also bail if the
            # session has gone idle for a long stretch (agent finished quietly).
            if msgs and not pending_tool:
                break
            if msgs:
                last_activity = time.monotonic()
            elif (time.monotonic() - last_activity) >= 600:
                break  # no messages at all for 10 min — assume done/stalled
        await _snapshot_opencode_db(run_id)
    except Exception as exc:
        logger.warning("legacy_finalizer[%s] error: %s", run_id, exc)
        try:
            await _snapshot_opencode_db(run_id)
        except Exception:
            pass
    finally:
        logger.info("legacy_finalizer[%s] exited", run_id)


def _arm_driver(run_id: str) -> None:
    """Start the phase-driver for a run if one is not already live."""
    existing = _phase_drivers.get(run_id)
    if existing and not existing.done():
        return
    _phase_drivers[run_id] = asyncio.create_task(_phase_driver(run_id))


# A2: no-progress stop-condition. If this many CONSECUTIVE phases each produce
# zero NEW verifier-CONFIRMED findings, the run is making no forward progress
# (de1e6112: privesc + cred-extraction + exfil-sim found nothing for ~44h). Force
# finalize instead of burning the whole phase chain.
NO_PROGRESS_PHASE_LIMIT = 2
# A5: per-phase tool-call cap (context-growth bound). A phase that fires this many
# tool calls without completing is in a loop (de1e6112 phase 7: ~700 commands).
# Force-complete it so the run moves on instead of growing context unbounded.
PHASE_MAX_TOOL_CALLS = 120


def _count_confirmed_verdicts(run_id: str) -> int:
    """Count of verifier-CONFIRMED findings for a run. Each finding is a
    <slug>.jsonl in OUTPUTS_DIR/<run_id>/verifier/; a CONFIRMED one carries a
    VERDICT record. Drives the no-progress stop-condition (A2)."""
    vdir = OUTPUTS_DIR / run_id / "verifier"
    if not vdir.exists():
        return 0
    n = 0
    for f in vdir.glob("*.jsonl"):
        try:
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                if (('"verdict"' in line and "CONFIRMED" in line)
                        or ('"ok_to_report"' in line and '"YES"' in line)):
                    n += 1
                    break
        except Exception:
            continue
    return n


async def _phase_driver(run_id: str) -> None:
    """Background loop: poll the active phase's session, detect turn-end, and
    either auto-advance or pause for review. Re-reads the manifest each tick so
    operator actions (advance / mode flip) are respected. Exits when the current
    phase is no longer RUNNING (advanced, stopped, or awaiting review)."""
    try:
        from ..services.container_addr import get_container_address
        from ..services.opencode_client import _ensure_network_connectivity, get_session_messages_async
        meta = _read_run_meta(run_id)
        container_id = meta.get("container_id", "")
        if not container_id:
            return
        await _ensure_network_connectivity(container_id)
        addr = await get_container_address(container_id)
    except Exception as exc:
        logger.warning("phase_driver[%s] init failed: %s", run_id, exc)
        return

    tracked_cur = -2
    tracked_epoch = 0
    last_sig = None
    stable_since: Optional[float] = None
    phase_started_local = 0.0
    confirmed_at_phase_start = 0
    tool_cap_hit = False

    while True:
        await asyncio.sleep(PHASE_POLL_S)
        meta = _read_run_meta(run_id)
        phases = meta.get("phases") or []
        rt = meta.get("phase_runtime") or []
        cur = meta.get("current_phase", -1)
        mode = meta.get("phase_mode", PhaseMode.REVIEW_EACH.value)
        if not phases or not (0 <= cur < len(rt)):
            break
        entry = rt[cur]
        if entry.get("status") != PhaseStatus.RUNNING.value:
            break
        sess = entry.get("session_id", "")
        if not sess:
            break

        # Reset idle/stable tracking whenever the active phase changes OR the
        # operator interrupts+restarts it (interrupt_epoch bump) — otherwise a
        # restarted phase inherits the old phase_started_local and times out at
        # once. Re-tracking on epoch makes a mid-phase interrupt a clean fresh start.
        cur_epoch = int(meta.get("interrupt_epoch", 0))
        if cur != tracked_cur or cur_epoch != tracked_epoch:
            tracked_cur = cur
            tracked_epoch = cur_epoch
            last_sig = None
            stable_since = None
            phase_started_local = time.time()
            confirmed_at_phase_start = _count_confirmed_verdicts(run_id)
            tool_cap_hit = False

        res = await get_session_messages_async(session_id=sess, host=addr, port=4096)
        msgs = res.get("messages", []) if res.get("success") else []
        pending_tool, final_text, activity = _detect_turn_complete(msgs)

        last_part_id = None
        if msgs:
            parts = msgs[-1].get("parts") or []
            if parts and isinstance(parts[-1], dict):
                last_part_id = parts[-1].get("id")
        sig = (
            len(msgs),
            (msgs[-1].get("info", {}) or {}).get("id") if msgs else None,
            last_part_id,
            sum(1 for m in msgs for p in (m.get("parts") or []) if isinstance(p, dict) and p.get("type") == "tool"),
        )
        now = time.time()
        if sig == last_sig:
            if stable_since is None:
                stable_since = now
        else:
            last_sig = sig
            stable_since = now
        idle = stable_since is not None and (now - stable_since) >= PHASE_IDLE_S

        sentinel = bool(final_text) and (PHASE_DONE_SENTINEL in final_text)
        max_s = int(meta.get("timeout_seconds") or PHASE_DEFAULT_MAX_S)
        # Time-based hard cap (not gated on `activity`): a phase whose session is dead
        # / unreachable / never produces output must STILL time out after max_s, else
        # the run hangs forever (the no-activity hang). 20 min is generous for a legit
        # cold start; a phase needing more can raise timeout_seconds.
        timed_out = (now - phase_started_local) >= max_s

        tool_calls = sig[3] if sig else 0
        complete = False
        if timed_out:
            complete = True
        elif tool_calls >= PHASE_MAX_TOOL_CALLS:
            tool_cap_hit = True
            complete = True
        elif sentinel and not pending_tool:
            complete = True
        elif activity and not pending_tool and final_text and idle:
            complete = True
        elif activity and not pending_tool and idle and not final_text:
            complete = True

        if not complete:
            continue

        # Choose the best forwardable summary for this phase, in priority order:
        #  1. the agent's own text when it left a concluding message (sentinel or
        #     not) — _extract_phase_summary strips a stray sentinel and isolates a
        #     'PHASE SUMMARY' header if present;
        #  2. a reconstructed digest of the phase's tool I/O — the glm-5.2 failure
        #     mode where the agent writes nothing useful but the findings live in
        #     the commands it ran.
        # Preferring (1) preserves what the agent itself concluded (and what the
        # report appendix / review gate show); the digest only fires when the
        # agent left no final text at all. This `result` is what later phases
        # receive as context.
        _agent_summary = _extract_phase_summary(final_text) if final_text else ""
        summary = (_agent_summary if _is_substantive_summary(_agent_summary) else "") \
            or _summarize_messages(msgs) or ""
        summary = summary.strip()
        if timed_out:
            summary = (summary + "\n[phase timed out — operator review]").strip() \
                if summary else "(phase timed out — no activity captured; review agent session)"
        elif tool_cap_hit:
            summary = (summary + f"\n[phase force-completed at {PHASE_MAX_TOOL_CALLS}-tool-call cap — possible loop]").strip()
        elif not summary:
            summary = "(no activity captured — review agent session)"

        # A2: no-progress stop. Count new CONFIRMED findings since this phase
        # started; if N consecutive phases produced none, finalize instead of
        # auto-advancing into more empty phases (de1e6112 looped ~44h on empties).
        confirmed_now = _count_confirmed_verdicts(run_id)
        meta["no_progress_phases"] = 0 if confirmed_now > confirmed_at_phase_start \
            else int(meta.get("no_progress_phases", 0)) + 1
        no_progress_stop = int(meta["no_progress_phases"]) >= NO_PROGRESS_PHASE_LIMIT
        if no_progress_stop:
            summary = (summary + f"\n[NO-PROGRESS STOP — {meta['no_progress_phases']} consecutive phases with no new confirmed finding]").strip()

        is_last = cur >= len(phases) - 1
        will_advance = (not is_last) and (mode == PhaseMode.AUTO_CONTINUE.value) and (not no_progress_stop)
        new_status = PhaseStatus.COMPLETED.value if will_advance else PhaseStatus.AWAITING_REVIEW.value
        rt[cur] = {
            **entry,
            "status": new_status,
            "result": summary,
            "completed_at": _now_iso(),
        }
        meta["phase_runtime"] = rt
        _atomic_write(_run_meta_path(run_id), meta)

        if not will_advance:
            break
        # auto_continue: start the next phase and keep looping.
        try:
            await _start_phase(run_id, cur + 1, addr)
            tracked_cur = -2  # force re-track for the new phase next tick
        except Exception as exc:
            logger.warning("phase_driver[%s] auto-advance to phase %d failed: %s", run_id, cur + 1, exc)
            break

    # "run/phase finished (for now)" hook: snapshot the ephemeral opencode.db
    # before the host can be recreated and lose it. Best-effort; fires on every
    # exit incl. review-gates and timeouts. (Mirrors _lead_driver's exit hook.)
    await _snapshot_opencode_db(run_id)
    logger.info("phase_driver[%s] exited", run_id)


@router.get("/runs/{run_id}/phases")
async def get_phases(run_id: str) -> Dict[str, Any]:
    """Phase chain + per-phase runtime state + whether the driver is live."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found; has the run been launched?")
    task = _phase_drivers.get(run_id) or _lead_drivers.get(run_id)
    live = bool(task and not task.done())

    rt = list(meta.get("phase_runtime") or [])

    # native_subagents: the active phase's subagent runs as a CHILD session of the
    # Lead. The driver persists phase_runtime[].session_id once it parses the
    # child id, but that id only appears in the Lead's task-tool OUTPUT on
    # completion — so while a phase is running (or if the driver isn't live, e.g.
    # after a backend restart) the field is empty and the console falls back to the
    # Lead session, hiding the subagent's commands. Resolve the child here via
    # parentID (read-only — augment the response only; the driver owns writes to
    # phase_runtime) so the stream follows the subagent regardless of driver state.
    orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
    if orch == Orchestration.NATIVE_SUBAGENTS.value and meta.get("session_id"):
        cur = meta.get("current_phase", -1)
        if 0 <= cur < len(rt):
            entry = rt[cur]
            running = entry.get("status") in (
                PhaseStatus.RUNNING.value, PhaseStatus.AWAITING_REVIEW.value,
            )
            if running and not entry.get("session_id"):
                try:
                    from ..services.container_addr import get_container_address
                    from ..services.opencode_client import _ensure_network_connectivity
                    cid = meta.get("container_id", "")
                    if cid:
                        await _ensure_network_connectivity(cid)
                        addr = await get_container_address(cid)
                        child = await _resolve_lead_child_session(meta.get("session_id", ""), addr)
                        if child:
                            entry = dict(entry)
                            entry["session_id"] = child
                            rt[cur] = entry
                except Exception as exc:
                    logger.debug("get_phases[%s] child resolve failed: %s", run_id, exc)

    return {
        "run_id": run_id,
        "phased": bool(meta.get("phases")),
        "phase_mode": meta.get("phase_mode", PhaseMode.REVIEW_EACH.value),
        "orchestration": orch,
        "current_phase": meta.get("current_phase", -1),
        "phases": meta.get("phases", []),
        "phase_runtime": rt,
        "live_driver": live,
    }


# =============================================================================
# Native subagent orchestration (orchestration=native_subagents)
#
# A SINGLE coder56_lead (primary) session coordinates the engagement, spawning a
# coder56_phase subagent per phase via opencode's Task tool. The subagents run as
# CHILD SESSIONS of the Lead and report back; the Lead aggregates. The driver
# below watches the ONE Lead session and derives `phase_runtime` from the Lead's
# coder56_phase task-tool calls (so /phases, the report, and the UI work unchanged
# vs the backend session-per-phase path). phase_mode (review_each / auto_continue)
# governs whether the Lead pauses between phases.
# =============================================================================

# Per-run lead-driver tasks (mirrors _phase_drivers).
_lead_drivers: Dict[str, asyncio.Task] = {}

# Regexes over a coder56_phase task tool's output, which opencode emits as:
#   <task id="ses_..." state="completed"><task_result>...report...</task_result></task>
_TASK_TAG_RE = re.compile(r'<task\b([^>]*)>', re.IGNORECASE)
_TASK_RESULT_RE = re.compile(r'<task_result>([\s\S]*?)</task_result>', re.IGNORECASE)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def _parse_lead_task(state: Dict[str, Any]) -> Dict[str, Any]:
    """Extract {objective, child_session_id, task_state, result} from a
    coder56_phase task-tool call's state. Returns {} if it isn't one.

    The Task tool's input carries subagent_type + prompt (OBJECTIVE/SCOPE/PRIOR);
    its output carries the child session id + the subagent's report."""
    inp = state.get("input") or {}
    if isinstance(inp, str):
        try:
            inp = json.loads(inp)
        except Exception:
            inp = {}
    if not isinstance(inp, dict):
        inp = {}
    sub = str(inp.get("subagent_type") or inp.get("subagentType") or "").strip()
    if sub != "coder56_phase":
        return {}
    prompt = str(inp.get("prompt") or "")
    obj = ""
    for line in prompt.splitlines():
        s = line.strip()
        if s.upper().startswith("OBJECTIVE:"):
            obj = s[len("OBJECTIVE:"):].strip()
            break
    if not obj:
        obj = prompt.strip().split("\n", 1)[0][:200]
    out = state.get("output") or ""
    out_s = out if isinstance(out, str) else safeStr(out)
    child = ""
    tstate = ""
    m = _TASK_TAG_RE.search(out_s)
    if m:
        for k, v in _ATTR_RE.findall(m.group(1)):
            if k.lower() == "id":
                child = v
            elif k.lower() == "state":
                tstate = v
    mr = _TASK_RESULT_RE.search(out_s)
    result = mr.group(1).strip() if mr else out_s.strip()
    return {"objective": obj, "child_session_id": child, "task_state": tstate, "result": result}


async def _resolve_lead_child_session(lead_sess: str, addr: str) -> str:
    """For a native_subagents run, find the coder56_phase child session the Lead
    is currently running. The Lead's task-tool output (which carries the child
    id inside <task id="...">) is empty until the task COMPLETES, so while a
    phase is live the child id is otherwise unknowable. We discover it via
    GET /session: every child session opencode spawns carries parentID == the
    Lead. Phases run strictly sequentially, so the newest child is the current
    phase's subagent. Returns '' if the Lead is unknown or no child/lookup.

    Used both by the lead driver (to persist phase_runtime[].session_id) and by
    /phases (so the console can follow the subagent's stream even when the
    driver isn't live — e.g. after a backend restart mid-run)."""
    if not lead_sess or not addr:
        return ""
    try:
        from ..services.opencode_client import list_session_objects_async
        sres = await list_session_objects_async(host=addr, port=4096)
        if not sres.get("success"):
            return ""
        kids = [
            s for s in (sres.get("sessions") or [])
            if isinstance(s, dict) and s.get("parentID") == lead_sess
        ]
        if not kids:
            return ""

        def _created(s: Dict[str, Any]) -> float:
            v = ((s.get("time") or {}).get("created")) or 0
            return v if isinstance(v, (int, float)) else 0

        return max(kids, key=_created).get("id", "") or ""
    except Exception as exc:
        logger.debug("resolve_lead_child_session failed: %s", exc)
        return ""


def _compile_lead_directive(meta: Dict[str, Any]) -> str:
    """The coordination prompt sent ONCE to the coder56_lead session at accept
    time. The Lead then drives the engagement by spawning a coder56_phase
    subagent per phase. Mirrors _compile_phase_directive's scope handling."""
    phases = meta.get("phases") or []
    mode = meta.get("phase_mode", PhaseMode.REVIEW_EACH.value)
    directive = (meta.get("directive") or "").strip()
    phase_lines = []
    for i, p in enumerate(phases):
        obj = _strip_phase_label((p.get("objective") or "").strip()) or f"(phase {i + 1}: see directive)"
        line = f"  Phase {i + 1}: {obj}"
        tools = p.get("tools") or []
        if tools:
            line += f"\n    Recommended tools: {', '.join(tools)}"
        checklist = p.get("checklist") or []
        if checklist:
            for item in checklist:
                line += f"\n    [ ] {item}"
        phase_lines.append(line)
    phases_block = "\n".join(phase_lines)
    if mode == PhaseMode.REVIEW_EACH.value:
        pacing = (
            "PACING (REVIEW mode): after EACH phase's subagent reports back and you record its "
            f"finding, emit the marker '{PHASE_DONE_SENTINEL}' on its own line and STOP. Do NOT "
            "begin the next phase until the operator sends you a message to continue."
        )
    else:
        pacing = (
            "PACING (AUTO mode): execute all phases back-to-back. After the final phase, write a "
            "concise ENGAGEMENT SUMMARY."
        )
    _lead = (
        "=== AUTHORIZED ENGAGEMENT (sanctioned cyber-range exercise) ===\n"
        "You are the LEAD coordinator. Execute the engagement below PHASE BY PHASE by delegating "
        "each phase to the coder56_phase subagent via the task tool.\n\n"
        "FULL ENGAGEMENT DIRECTIVE (your authorized scope — stay strictly within it and pass it "
        f"verbatim to each subagent):\n{directive}\n\n"
        f"{PHASE0_TARGET_VALIDATION_BLOCK}\n"
        "PHASES (execute in order):\n"
        f"{phases_block}\n\n"
        f"{pacing}\n\n"
        "For each phase:\n"
        "1. Call the task tool with subagentType 'coder56_phase'. The task prompt MUST include: the "
        "PHASE OBJECTIVE, the AUTHORIZED SCOPE (verbatim from the directive above), recommended "
        "tools/checklist, the accumulated PRIOR PHASE FINDINGS in full, and this exact contract: "
        "`MEMORY FIRST: read "
        "/outputs/$RUN_ID/memory/MEMORY.md before any other action; trust established records; "
        "coordinate through [CLAIMED]/[DONE]; execute only the phase-specific delta; append every "
        "broadly useful discovery immediately. VERIFIER GATE (mandatory): before you report any "
        "finding as a vulnerability, you MUST delegate it to the coder56_verifier subagent via the "
        "task tool (subagentType coder56_verifier) and gate on its OK TO REPORT: token; include a "
        "## VERIFIER CALLS section in your report proving each delegated finding with the token + "
        "cited /outputs/$RUN_ID/verifier/*.jsonl. Recon facts need no gate. If the verifier task "
        "fails to launch, emit === VERIFIER UNAVAILABLE: <reason> === and list the candidate as "
        "unverified; do not report it as a finding. Prefer the matching hexstrike-ai_* MCP tool "
        "over its bash CLI. PERSIST COVERAGE: append one TESTED|method=...|path=...|params=...|"
        "role=...|status=...|evidence=... line per endpoint x param x role you actually exercised.` "
        "The explicit prior summaries and shared memory "
        "are complementary handoffs; neither authorizes repeating established work.\n"
        "2. When the subagent reports back, record only a concise summary of the NEW DELTA; do "
        "not restate inherited memory facts as new findings.\n"
        "3. Follow the PACING rule above.\n"
        "=== END ==="
    )
    return _resolve_run_paths(_lead, meta.get("run_id", ""))


async def _graceful_finalize_session(session_id: str, addr: str, timeout_s: int = 75, run_id: str = "") -> None:
    """P1-3: best-effort graceful wrap-up BEFORE a backstop gates/kills a running
    phase or verifier session. Sends one short 'emit your final summary / verdict
    now' turn and waits bounded for a response. Never raises — a wedged session
    simply falls through to the truncation marker, and the verifier's audit-file
    VERDICT record (coder56_verifier step j) + the engagement memory
    already preserve the substantive work. The session keeps its own agent."""
    if not session_id or not addr:
        return
    try:
        from ..services.opencode_client import send_prompt_async
        _fin_prompt = (
            "ENGAGEMENT TIME BUDGET EXPIRED — wrap up NOW in one short turn. Emit your final "
            "structured report (WHAT YOU DID / WHAT YOU FOUND / NEXT STEP). If you are verifying "
            "or mid-verification, FIRST append your VERDICT record to /outputs/$RUN_ID/verifier/<slug>.jsonl "
            "(step j) and emit the === VERIFIER VERDICT === block. Do not start new commands — "
            "summarize from what you already have, then stop."
        )
        await send_prompt_async(
            session_id=session_id,
            prompt=_resolve_run_paths(_fin_prompt, run_id),
            host=addr, port=4096, async_mode=False, timeout=timeout_s,
        )
    except Exception as exc:
        logger.warning("graceful_finalize[%s] best-effort send failed (continuing): %s", session_id, exc)


def _read_verdicts_tail(run_id: str, limit: int = 64) -> List[Dict[str, Any]]:
    """Newest-first tail of the guardrail verdicts.ndjson for a run. Each line is
    {decision, reason, tokens:{total,...}, ...}. Best-effort: missing/garbage file
    => []. Used by the circuit breaker (consecutive dead-judge) and the escalate
    gate (any undecided escalate)."""
    path = _guardrail_dir(run_id) / "verdicts.ndjson"
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _last_assistant_text(messages: List[Dict[str, Any]]) -> str:
    """Last non-empty assistant text part from an opencode message list. Mirrors the
    role/parts shape consumed in _lead_driver (role in m["role"] or m["info"]["role"];
    text in parts where type=="text"). Used by the result-capture fallback (FIX#3)."""
    for m in reversed(messages or []):
        if not isinstance(m, dict):
            continue
        if (m.get("role") or (m.get("info") or {}).get("role")) != "assistant":
            continue
        for p in reversed(m.get("parts") or []):
            if isinstance(p, dict) and p.get("type") == "text" and (p.get("text") or "").strip():
                return p["text"]
    return ""


def _phase_had_tool_calls(run_id: str, started_at: str, completed_at: str) -> bool:
    """True if any guardrail verdict was logged in [started_at, completed_at]. Every
    bash + MCP tool call is guardrail-gated, so a verdict in-window == the phase
    executed real work. Used by the AUTO completion gate (FIX#4) to reject hollow
    'completed' phases (0 tool calls, e.g. a model spawn-crash). Fails open (True)
    on a missing started_at or read error so a glitch can't falsely gate a phase."""
    if not started_at:
        return True
    try:
        path = _guardrail_dir(run_id) / "verdicts.ndjson"
        if not path.exists():
            return False
        lo = started_at[:19]
        hi = (completed_at or _now_iso())[:19]
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                ts = (obj.get("ts") or obj.get("timestamp") or "")[:19]
                if ts and lo <= ts <= hi:
                    return True
        return False
    except Exception:
        return True


def _verdict_is_dead_judge(v: Dict[str, Any]) -> bool:
    """True when the JUDGE itself produced no usable verdict (not a deliberate
    refuse/escalate). Matches run b1425481: 88/88 verdicts decision='escalate',
    tokens.total==0, reason='...no assistant text (attempt 3/3)'."""
    if not isinstance(v, dict):
        return False
    toks = v.get("tokens") or {}
    if int(toks.get("total") or 0) == 0:
        return True
    reason = str(v.get("reason") or "")
    return bool(_RE_DEAD_JUDGE_REASON.search(reason))


def _consecutive_dead_judge(run_id: str) -> int:
    """Count of TRAILING verdicts that are dead-judge (scanning newest -> oldest,
    stopping at the first live verdict). 3 in a row = judge is down for the whole
    recent window => circuit-breaker trip."""
    verdicts = _read_verdicts_tail(run_id, limit=128)
    n = 0
    for v in reversed(verdicts):
        if _verdict_is_dead_judge(v):
            n += 1
        else:
            break
    return n


def _undecided_escalate_count(run_id: str) -> int:
    """Count of pending operator approvals whose guardrail verdict was 'escalate'
    AND that have no decision file yet. These block phase advance / run completion
    under judge_fail=escalate: an undecided escalate means a command is held for
    operator review, so the run is NOT actually free to proceed. Files are
    guardrail-authored <id>.req.json + operator <id>.dec.json (see _scan_approvals).
    Best-effort; a missing approvals dir => 0."""
    d = _approvals_dir(run_id)
    if not d.exists():
        return 0
    n = 0
    for req_file in d.glob("*.req.json"):
        try:
            raw = json.loads(req_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        gv = raw.get("guardrail_verdict") or {}
        if str(gv.get("decision") or "").lower() != "escalate":
            continue
        req_id = raw.get("id", req_file.stem)
        # Decided-ness is derived solely from the presence of <id>.dec.json.
        if _dec_path(run_id, req_id).exists():
            continue
        n += 1
    return n


def _count_session_parts(msgs: Any) -> int:
    """Total non-empty message parts across a session's message list. A lead/phase
    session that produced 0 parts never really ran (the agent emitted nothing) —
    the no-op failure detector marks the run failed rather than completed.
    Reference run 71592e76 (fabricated deliverables from an empty session)."""
    if not isinstance(msgs, list):
        return 0
    total = 0
    for m in msgs:
        if not isinstance(m, dict):
            continue
        parts = m.get("parts") or []
        if isinstance(parts, list):
            total += sum(1 for p in parts if isinstance(p, dict) and p.get("type"))
    return total


def _halt_run_failed(meta: Dict[str, Any], rt: List[Dict[str, Any]], reason: str) -> None:
    """Mark a run FAILED / needs-operator in place on the manifest: set the durable
    status flag + a human-readable failure_reason, and annotate the highest RUNNING
    phase so the UI/report show WHY (rather than silently flipping everything to
    COMPLETED like the pre-fix auto_continue path). _run_overall_status is
    status-driven, so we encode the halt via a manifest-level status override that
    takes precedence (see _run_overall_status patch)."""
    meta["status"] = "failed"
    meta["halted"] = True
    meta["needs_operator"] = True
    meta["failure_reason"] = reason
    note = f"[RUN HALTED — {reason}]"
    gate_idx = -1
    for i in range(len(rt)):
        if rt[i].get("status") == PhaseStatus.RUNNING.value:
            gate_idx = i
    if gate_idx < 0:
        gate_idx = len(rt) - 1
    if 0 <= gate_idx < len(rt):
        prev = rt[gate_idx].get("result", "") or ""
        rt[gate_idx]["result"] = (prev + "\n" + note).strip() if prev else note


def _arm_lead_driver(run_id: str) -> None:
    """Start the lead-driver for a run if one is not already live."""
    existing = _lead_drivers.get(run_id)
    if existing and not existing.done():
        return
    _lead_drivers[run_id] = asyncio.create_task(_lead_driver(run_id))


def _lead_needs_auto_resume(*, mode: str, pending_tool: bool,
                            lead_turn_complete: bool, n_completed: int,
                            n_tasks: int, n_phases: int) -> bool:
    """Return True when AUTO mode has an idle Lead stranded at a phase boundary.

    This can happen when the operator flips REVIEW -> AUTO after acceptance: the
    immutable Lead prompt still contains REVIEW pacing, so the Lead stops after
    its current phase even though run.json now says AUTO. The driver must resume
    that idle Lead explicitly instead of waiting for the stall watchdog.
    """
    return (
        mode == PhaseMode.AUTO_CONTINUE.value
        and not pending_tool
        and lead_turn_complete
        and n_completed >= 1
        and n_completed == n_tasks
        and n_tasks < n_phases
    )


async def _lead_driver(run_id: str) -> None:
    """Watch the coder56_lead session: derive phase_runtime from its coder56_phase
    task-tool calls and gate between phases per phase_mode. Mirrors _phase_driver
    but polls ONE session and parses task-tool I/O (the subagents are child
    sessions it spawns). Exits when the current phase is no longer RUNNING (a
    phase was gated for review, the run finished, or it was stopped)."""
    try:
        from ..services.container_addr import get_container_address
        from ..services.opencode_client import (
            _ensure_network_connectivity,
            get_session_messages_async,
            send_prompt_async,
        )
        meta = _read_run_meta(run_id)
        container_id = meta.get("container_id", "")
        if not container_id:
            return
        await _ensure_network_connectivity(container_id)
        addr = await get_container_address(container_id)
    except Exception as exc:
        logger.warning("lead_driver[%s] init failed: %s", run_id, exc)
        return

    lead_started = time.time()
    last_progress = time.time()     # last time a phase completed or a task spawned
    prev_n_completed = -1
    prev_n_tasks = -1
    gated_through = -1  # highest phase index already gated to awaiting_review
    auto_resumed_after = -1  # completion count already nudged in this driver
    phase0_nudged = False  # one-shot: Phase-0 THREAT_MODEL| nudge already sent
    corrected_for = -1  # phase index already given a corrective task payload
    last_snapshot = time.time()  # mid-run transcript snapshot cadence

    while True:
        try:
            await asyncio.sleep(PHASE_POLL_S)
            meta = _read_run_meta(run_id)
            if meta.get("orchestration") != Orchestration.NATIVE_SUBAGENTS.value:
                break
            phases = meta.get("phases") or []
            rt = meta.get("phase_runtime") or []
            mode = meta.get("phase_mode", PhaseMode.REVIEW_EACH.value)
            lead_sess = meta.get("session_id", "")
            if not phases or not lead_sess:
                break

            res = await get_session_messages_async(session_id=lead_sess, host=addr, port=4096)
            msgs = res.get("messages", []) if res.get("success") else []

            # Ordered list of coder56_phase task-tool calls + their parsed data + status,
            # plus the Lead's latest assistant text and whether any tool is still pending.
            tasks: List[tuple] = []
            final_text = ""
            pending_tool = False
            lead_turn_complete = False
            for m in msgs:
                for p in (m.get("parts") or []):
                    if not isinstance(p, dict):
                        continue
                    if p.get("type") == "tool":
                        st = p.get("state") or {}
                        status = st.get("status")
                        if status and status not in ("completed", "error"):
                            pending_tool = True
                        if p.get("tool") in ("task", "Task"):
                            # A spawn that ERRORED (schema/launch failure) never ran
                            # a phase — it must NOT consume a phase slot. Without
                            # this, a model that retries a malformed task call N
                            # times (qwen3.8-27b omitted the required `prompt` key
                            # 8x) index-shifts every later task past the runtime
                            # list: phantom phases "running", and the one REAL
                            # spawn lands beyond len(phases) where its results are
                            # never harvested (run fa816e74).
                            if status == "error":
                                continue
                            parsed = _parse_lead_task(st)
                            if parsed:
                                tasks.append((parsed, status))
                info = m.get("info") or {}
                if (info.get("role") or m.get("role")) == "assistant":
                    # Reassigned for every assistant message, leaving the value
                    # from the latest one. A completed turn with no pending tool
                    # is a genuine idle boundary, not a brief gap mid-response.
                    mtime = info.get("time") or m.get("time") or {}
                    lead_turn_complete = bool(mtime.get("completed") or mtime.get("end"))
                    for p in (m.get("parts") or []):
                        if isinstance(p, dict) and p.get("type") == "text" and (p.get("text") or "").strip():
                            final_text = p.get("text")

            # While a coder56_phase task is RUNNING its output is still None, so the
            # child session id is not yet parseable from the task state (_parse_lead_task
            # reads it from the <task id="..."> that only appears on completion). Resolve
            # it from the /session listing instead (child sessions carry parentID == lead).
            running_child_id = ""
            if any(st != "completed" and not parsed.get("child_session_id") for parsed, st in tasks):
                running_child_id = await _resolve_lead_child_session(lead_sess, addr)

            # Record each task (index-aligned to phase_runtime). Running tasks mark the
            # phase RUNNING; completed tasks record the subagent's report + child session.
            changed = False
            for idx, (parsed, status) in enumerate(tasks):
                if idx >= len(rt):
                    break
                entry = rt[idx]
                child = parsed.get("child_session_id") or (running_child_id if status != "completed" else "")
                obj = parsed.get("objective") or ""
                if status != "completed":
                    if entry.get("status") == PhaseStatus.PENDING.value:
                        entry["status"] = PhaseStatus.RUNNING.value
                        if obj:
                            entry["objective"] = obj
                        entry["started_at"] = entry.get("started_at") or _now_iso()
                        changed = True
                    if child and entry.get("session_id") != child:
                        entry["session_id"] = child
                        changed = True
                    continue
                if (not entry.get("result")) or (entry.get("status") in (PhaseStatus.PENDING.value, PhaseStatus.RUNNING.value)):
                    _result = parsed.get("result") or ""
                    # FIX#3 result-capture fallback: the Lead's structured summary is
                    # sometimes empty even though the phase subagent did real work
                    # (erpnext Phase 1 enumerated 11 users but phase_runtime.result
                    # was recorded as "" — starved the finding-driven re-planner).
                    # Pull the phase CHILD session's last assistant text directly.
                    if not _result and child:
                        try:
                            cres = await get_session_messages_async(session_id=child, host=addr, port=4096)
                            if cres.get("success"):
                                _result = _last_assistant_text(cres.get("messages", []))
                        except Exception as exc:
                            logger.warning("lead_driver[%s] phase %d result fallback failed: %s", run_id, idx, exc)
                    entry["result"] = _result
                    # VERIFIER-GATE GUARD (advisory, non-blocking): if this phase's
                    # OWN findings region asserts a vulnerability but shows no
                    # ## VERIFIER CALLS / OK TO REPORT: YES and no === VERIFIER
                    # UNAVAILABLE === marker, the verification gate was skipped.
                    # Annotate so the operator/UI/reporter sees the claims are
                    # UNVERIFIED. Scoped to the findings region + a strong signal to
                    # avoid false-annotating recon prose or echoed prior-block text.
                    _res = entry.get("result", "") or ""
                    if _res:
                        _region = _res.rsplit("WHAT YOU FOUND", 1)[-1]
                        _vuln_asserted = re.search(
                            r"(?im)(^\s*##\s*[FD]?\d*[^\n]*\b(idor|bfla|bola|sqli|sql injection|injection|auth(?:oriz|ent)?(?:\s* bypass)?|priv(?:ilege)?\s*esc|rate[- ]?limit|plaintext|unauth(?:orized)?|exposure|missing auth)\b"
                            r"|\b(confirmed|vulnerability|vuln:|exploitable)\b[^.\n]{0,80}\b(critical|high|medium|low|idor|bfla|injection|bypass|escalat|plaintext|exposure|rate[- ]?limit)\b)",
                            _region,
                        )
                        _verifier_evidence = re.search(r"(?im)(##\s*VERIFIER CALLS|OK\s+TO\s+REPORT\s*:\s*YES|VERIFIER UNAVAILABLE)", _res)
                        if _vuln_asserted and not _verifier_evidence:
                            entry["result"] = (_res + "\n[BACKEND VERIFIER-GATE GUARD: this phase asserts a vulnerability but contains no ## VERIFIER CALLS / OK TO REPORT: YES and no === VERIFIER UNAVAILABLE === marker. All vuln claims are UNVERIFIED — the verification gate was skipped.]").strip()
                            logger.warning("lead_driver[%s] phase %d reported a vuln with no verifier delegation; claims marked unverified", run_id, idx)
                    if child:
                        entry["session_id"] = child
                    if obj:
                        entry["objective"] = obj
                    entry["completed_at"] = entry.get("completed_at") or _now_iso()
                    changed = True
                if (
                    mode == PhaseMode.AUTO_CONTINUE.value
                    and entry.get("status") != PhaseStatus.COMPLETED.value
                ):
                    # In AUTO mode a returned task is a completed phase even
                    # while the Lead moves on. Keeping it "running" makes the UI
                    # and /guide target the previous child during the next phase.
                    # FIX#4 no-op gate: a phase that produced NO result AND made NO
                    # tool calls (zero guardrail verdicts in its window) did no real
                    # work — a model non-response/spawn-crash (erpnext Phase 4/5).
                    # Do NOT stamp it COMPLETED; flag AWAITING_REVIEW so the hollow
                    # green checkmark can't masquerade as done. The run continues.
                    _did_work = bool((entry.get("result") or "").strip()) or _phase_had_tool_calls(
                        run_id, entry.get("started_at") or "", entry.get("completed_at") or _now_iso())
                    if _did_work:
                        entry["status"] = PhaseStatus.COMPLETED.value
                    else:
                        entry["status"] = PhaseStatus.AWAITING_REVIEW.value
                        _prev_r = entry.get("result", "") or ""
                        entry["result"] = (_prev_r + "\n[BACKEND NO-OP GATE: phase returned with no "
                                           "captured result and zero tool calls in its window — likely a "
                                           "model non-response/spawn-crash. NOT marked complete; operator "
                                           "review required.]").strip()
                        logger.warning("lead_driver[%s] phase %d returned with no work (0 tool calls, "
                                       "empty result) — flagged AWAITING_REVIEW", run_id, idx)
                    changed = True

            n_completed = sum(1 for _, s in tasks if s == "completed")
            # Progress = a phase completed OR a new task spawned. Reset the stall clock
            # whenever the Lead is demonstrably advancing, so a long but healthy
            # multi-phase engagement is NOT falsely gated (the old per-run timeout did).
            if n_completed != prev_n_completed or len(tasks) != prev_n_tasks:
                last_progress = time.time()
                prev_n_completed = n_completed
                prev_n_tasks = len(tasks)

            # Phase-0 guard for auto_continue (best-effort one-shot — never blocks
            # the driver, per A4): if Phase 0 has completed (n_completed >= 1) but
            # engagement memory still lacks THREAT_MODEL|, nudge the Lead once to
            # complete scoping before it grinds into deep testing. The review_each
            # hard gate lives in advance_phase; this covers the auto path.
            if (n_completed >= 1 and not phase0_nudged
                    and not _phase0_complete(meta.get("engagement_id"))):
                phase0_nudged = True
                try:
                    await send_prompt_async(
                        session_id=lead_sess, host=addr, port=4096,
                        agent="coder56_lead", async_mode=True, timeout=30,
                        prompt=(
                            "Your Phase 0 completed but engagement memory still has no THREAT_MODEL| "
                            "record, so scoping is incomplete. Append the THREAT_MODEL|app=…|jewels=…|"
                            "sensitive_data=…|trust_boundaries=…|data_flows=…|attacker_goals=…|"
                            "risk_priorities=…|owasp_backstop=… line to engagement memory now (and "
                            "TARGET_IDENTITY| if missing) before proceeding with deep testing."
                        ),
                    )
                    last_progress = time.time()
                except Exception as exc:
                    logger.warning("lead_driver[%s] phase0 nudge failed: %s", run_id, exc)

            # qwen3.8 corrective injection (one-shot per phase): the lead repeatedly
            # emits task calls missing the required `prompt` key and narrates the
            # fix without applying it (run 883ea6af: 7+ consecutive SchemaErrors,
            # zero spawns). Hand it the EXACT ready-to-use JSON built from the real
            # phase objective so it only echoes, never composes.
            err_parts = sum(
                1
                for m in msgs
                for p in (m.get("parts") or [])
                if isinstance(p, dict)
                and p.get("type") == "tool"
                and p.get("tool") in ("task", "Task")
                and (p.get("state") or {}).get("status") == "error"
            )
            next_idx = min(n_completed, len(phases) - 1)
            if (
                err_parts >= 3
                and corrected_for != next_idx
                and not any(st == "running" for _, st in tasks)
            ):
                corrected_for = next_idx
                _obj = str(
                    phases[next_idx].get("objective")
                    or phases[next_idx].get("title")
                    or "execute this phase's objective"
                )[:500]
                _m = re.search(
                    r"AUTHORIZED SCOPE[^:\n]*:\s*\n(.+?)(?:\n\s*\n|\n[A-Z])",
                    meta.get("directive", ""),
                    re.S,
                )
                _scope = (_m.group(1).strip().splitlines()[0] if _m else "per the engagement directive")
                _payload = {
                    "description": f"Phase {next_idx}",
                    "prompt": (
                        f"OBJECTIVE: {_obj}\n"
                        f"AUTHORIZED SCOPE: {_scope}\n"
                        f"prior findings: read /outputs/{run_id}/memory/MEMORY.md"
                    ),
                    "subagent_type": "coder56_phase",
                }
                try:
                    await send_prompt_async(
                        session_id=lead_sess,
                        host=addr,
                        port=4096,
                        agent="coder56_lead",
                        async_mode=True,
                        timeout=30,
                        prompt=(
                            f"Your last {err_parts} task calls were rejected: you keep omitting the required "
                            "`prompt` key while believing you included it. Stop composing the JSON yourself. "
                            "Call the task tool NOW with EXACTLY this payload (copy it verbatim, all three keys):\n"
                            + json.dumps(_payload, ensure_ascii=False)
                            + "\nSend it as-is; do not shorten, rename, or reorder keys."
                        ),
                    )
                    last_progress = time.time()
                except Exception as exc:
                    logger.warning("lead_driver[%s] corrective injection failed: %s", run_id, exc)

            now = time.time()
            # Periodic mid-run transcript snapshot: the exit snapshot at driver
            # exit (below) covers phase boundaries; this covers a mid-phase host
            # recreate/crash so the full execution is never lost. Best-effort.
            if (now - last_snapshot) >= RUN_SNAPSHOT_CADENCE_S:
                await _snapshot_opencode_db(run_id)
                last_snapshot = now

            # === REC#3 SAFETY GATES (fire every poll, before any completion mark) ===
            # These prevent the b1425481 / 71592e76 failure modes: a dead guardrail
            # judge makes every command escalate, yet auto_continue used to mark all
            # phases 'completed'. Each gate halts the run FAILED/needs-operator,
            # snapshots the transcript, and exits WITHOUT faking completion.
            halt_reason = ""
            # (c) NO-OP FAILURE DETECTOR: the Lead session produced no parts at all —
            # the agent never really ran. Fabricating deliverables (71592e76) is
            # worse than an honest failure.
            if not msgs:
                halt_reason = "no-op session: lead session produced 0 messages/parts — the agent never ran (no transcript to report)"
            # (b) CONSECUTIVE-FAIL CIRCUIT BREAKER: >=3 dead-judge verdicts in a row
            # (judge unreachable / empty body). Stop burning retries.
            elif _consecutive_dead_judge(run_id) >= GUARDRAIL_CIRCUIT_BREAKER_N:
                halt_reason = (f"circuit breaker: {GUARDRAIL_CIRCUIT_BREAKER_N}+ consecutive guardrail "
                               "verdicts had tokens.total==0 / no-verdict (judge unreachable). Run paused "
                               "to stop burning retries; flip judge-fail to 'allow' or restore the judge "
                               "and restart the run")
            # (a) UNDECIDED-ESCALATE GATE: a pending escalate approval is an open
            # operator hold. judge_fail=escalate must NOT let the run advance /
            # complete while a command is still awaiting a human decision.
            elif _undecided_escalate_count(run_id) > 0 and not meta.get("halted"):
                # Pause (awaiting operator) rather than hard-fail: an undecided
                # escalate is a recoverable human-in-the-loop hold, not a crash.
                # We DO NOT mark remaining phases completed; we just stop here.
                gate_idx_e = -1
                for i in range(len(rt)):
                    if rt[i].get("status") == PhaseStatus.RUNNING.value:
                        gate_idx_e = i
                if gate_idx_e < 0:
                    gate_idx_e = max(0, (sum(1 for _, s in tasks if s == "completed") - 1))
                if 0 <= gate_idx_e < len(rt) and rt[gate_idx_e].get("status") not in (
                    PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value,
                ):
                    rt[gate_idx_e]["status"] = PhaseStatus.AWAITING_REVIEW.value
                    prev = rt[gate_idx_e].get("result", "") or ""
                    rt[gate_idx_e]["result"] = (prev + "\n[phase gated — one or more guardrail escalate verdicts await operator decision; resolve them before the run can advance]").strip() if prev else "[phase gated — one or more guardrail escalate verdicts await operator decision; resolve them before the run can advance]"
                    meta["current_phase"] = gate_idx_e
                meta["phase_runtime"] = rt
                meta["pending_escalates"] = _undecided_escalate_count(run_id)
                _atomic_write(_run_meta_path(run_id), meta)
                await _snapshot_opencode_db(run_id)
                break  # exit driver; run stays awaiting_review until the operator decides
            if halt_reason and not meta.get("halted"):
                _halt_run_failed(meta, rt, halt_reason)
                meta["phase_runtime"] = rt
                _atomic_write(_run_meta_path(run_id), meta)
                await _snapshot_opencode_db(run_id)
                logger.error("lead_driver[%s] HALTING run: %s", run_id, halt_reason)
                break  # exit the driver — run is failed/needs-operator, NOT completed

            per_phase_max = int(meta.get("timeout_seconds") or PHASE_DEFAULT_MAX_S)
            # stalled = no forward progress for a whole phase budget — catches a Lead
            # blocked on a hung task call (its messages go quiet) regardless of how many
            # phases parsed. hard_cap = whole-run backstop. Either -> gate + exit.
            stalled = (now - last_progress) >= per_phase_max
            hard_cap = (now - lead_started) >= per_phase_max * max(1, len(phases))

            # The phase to gate on stall/timeout = highest RUNNING (what the Lead is
            # stuck on); fall back to the last completed / first phase. Robust to the
            # desync where n_completed under-reports the Lead's true position.
            gate_idx = -1
            for i in range(len(rt)):
                if rt[i].get("status") == PhaseStatus.RUNNING.value:
                    gate_idx = i
            if gate_idx < 0:
                gate_idx = max(0, n_completed - 1)

            # P1-3: graceful finalization on backstop. Give the running phase child a
            # short, bounded chance to emit its final summary / VERDICT before we gate.
            # Best-effort (never raises); the verdict checkpoint + MEMORY.md remain the
            # durable backstops if the session is already wedged.
            if (stalled or hard_cap) and 0 <= gate_idx < len(rt):
                _gchild = rt[gate_idx].get("session_id", "")
                if _gchild:
                    await _graceful_finalize_session(_gchild, addr, run_id=run_id)

            # Gate logic.
            done = False
            gated_now = False
            if mode == PhaseMode.REVIEW_EACH.value:
                # Pause when the Lead emitted the sentinel after a freshly-completed phase.
                if not pending_tool and n_completed >= 1 and (n_completed - 1) > gated_through and PHASE_DONE_SENTINEL in (final_text or ""):
                    rt[n_completed - 1]["status"] = PhaseStatus.AWAITING_REVIEW.value
                    gated_through = n_completed - 1
                    changed = True
                    done = True
                elif stalled or hard_cap:
                    if 0 <= gate_idx < len(rt) and rt[gate_idx].get("status") not in (PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value):
                        rt[gate_idx]["status"] = PhaseStatus.AWAITING_REVIEW.value
                        prev = rt[gate_idx].get("result", "")
                        rt[gate_idx]["result"] = (prev + f"\n[phase finalized under time budget — partial result; full findings in {_run_memory_path(run_id)}, verifier verdicts in /outputs/{run_id}/verifier/]").strip() \
                            if prev else f"[phase finalized under time budget — partial result; full findings in {_run_memory_path(run_id)}, verifier verdicts in /outputs/{run_id}/verifier/]"
                    gated_through = gate_idx
                    gated_now = True
                    changed = True
                    done = True
            else:  # auto_continue
                if not pending_tool and n_completed >= len(phases):
                    # REC#3(a): do NOT auto-complete while an escalate verdict is
                    # still awaiting operator decision under judge_fail=escalate.
                    # Gate to awaiting_review instead (the per-poll undecided-
                    # escalate break covers the common case; this guards the exact
                    # boundary iteration).
                    _pending_esc = _undecided_escalate_count(run_id)
                    if _pending_esc > 0:
                        gate_idx_e = max(0, n_completed - 1)
                        if 0 <= gate_idx_e < len(rt) and rt[gate_idx_e].get("status") not in (
                            PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value,
                        ):
                            rt[gate_idx_e]["status"] = PhaseStatus.AWAITING_REVIEW.value
                        meta["pending_escalates"] = _pending_esc
                        changed = True
                        done = True
                    else:
                        for i in range(len(rt)):
                            if rt[i].get("status") not in (PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value):
                                rt[i]["status"] = PhaseStatus.COMPLETED.value
                        changed = True
                        done = True
                elif (not pending_tool and lead_turn_complete
                      and _RE_OBJECTIVE_MET.search(final_text or "")):
                    # M9 (C7.2 + A1): the Lead intentionally stopped early because the
                    # engagement OBJECTIVE is already met (it emitted OBJECTIVE ALREADY
                    # MET). Respect that — mark remaining phases COMPLETED with an
                    # objective-met note instead of auto-resuming them (auto-resume would
                    # grind past a solved objective). No new SATISFIED enum: COMPLETED
                    # keeps _run_overall_status correct. Category-level CATEGORY OBJECTIVE
                    # MET does NOT halt here — the Lead may still continue to other
                    # categories; only the engagement-level gate halts the run.
                    for i in range(len(rt)):
                        if rt[i].get("status") not in (PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value):
                            rt[i]["status"] = PhaseStatus.COMPLETED.value
                            prev = rt[i].get("result", "")
                            note_txt = "[OBJECTIVE ALREADY MET — phase not executed; the engagement objective was satisfied earlier in the run]"
                            rt[i]["result"] = (prev + "\n" + note_txt).strip() if prev else note_txt
                    changed = True
                    done = True
                elif _lead_needs_auto_resume(
                    mode=mode,
                    pending_tool=pending_tool,
                    lead_turn_complete=lead_turn_complete,
                    n_completed=n_completed,
                    n_tasks=len(tasks),
                    n_phases=len(phases),
                ) and auto_resumed_after != n_completed:
                    # AUTO may have been selected after accept, while the Lead's
                    # original prompt still says REVIEW. Override that stale
                    # pacing instruction at the first idle phase boundary.
                    next_phase = n_completed + 1
                    sres = await send_prompt_async(
                        session_id=lead_sess,
                        prompt=(
                            "Runtime pacing is now AUTO_CONTINUE. This explicitly overrides any "
                            "earlier REVIEW/stop-at-boundary instruction. "
                            f"Phase {n_completed} is complete; proceed to phase {next_phase} now: "
                            "spawn its coder56_phase subagent, record the findings, and continue "
                            "all remaining phases back-to-back without waiting for operator review."
                        ),
                        host=addr,
                        port=4096,
                        agent="coder56_lead",
                        async_mode=True,
                        timeout=30,
                    )
                    if sres.get("success"):
                        auto_resumed_after = n_completed
                        last_progress = time.time()
                        logger.info(
                            "lead_driver[%s] resumed idle Lead for AUTO phase %d",
                            run_id, next_phase,
                        )
                    else:
                        logger.warning(
                            "lead_driver[%s] AUTO resume failed after phase %d: %s",
                            run_id, n_completed, sres.get("error"),
                        )
                elif stalled or hard_cap:
                    if 0 <= gate_idx < len(rt) and rt[gate_idx].get("status") not in (PhaseStatus.AWAITING_REVIEW.value, PhaseStatus.COMPLETED.value):
                        rt[gate_idx]["status"] = PhaseStatus.AWAITING_REVIEW.value
                        prev = rt[gate_idx].get("result", "")
                        rt[gate_idx]["result"] = (prev + f"\n[phase finalized under time budget — partial result; full findings in {_run_memory_path(run_id)}, verifier verdicts in /outputs/{run_id}/verifier/]").strip() \
                            if prev else f"[phase finalized under time budget — partial result; full findings in {_run_memory_path(run_id)}, verifier verdicts in /outputs/{run_id}/verifier/]"
                    gated_now = True
                    changed = True
                    done = True

            if changed:
                meta["phase_runtime"] = rt
                if gated_now and gate_idx >= 0:
                    meta["current_phase"] = gate_idx
                elif any(e.get("status") == PhaseStatus.RUNNING.value for e in rt):
                    meta["current_phase"] = max(
                        i for i, e in enumerate(rt)
                        if e.get("status") == PhaseStatus.RUNNING.value
                    )
                elif n_completed:
                    meta["current_phase"] = n_completed - 1
                else:
                    meta["current_phase"] = meta.get("current_phase", 0)
                _atomic_write(_run_meta_path(run_id), meta)
            if done:
                break

        except Exception as exc:
            # CRITICAL: a transient error (opencode API blip, JSON parse, container
            # hiccup) must NOT kill this driver. If it dies, nothing watches the Lead,
            # no stall/timeout ever fires, and the engagement hangs indefinitely (the
            # 12h-stuck failure mode). Log, back off, keep watching.
            logger.warning("lead_driver[%s] iteration error (continuing): %s", run_id, exc)
            await asyncio.sleep(PHASE_POLL_S * 2)
            continue

    # The driver only exits at a phase boundary / run end / stall, so this is the
    # "run finished (for now)" hook: snapshot the ephemeral opencode.db (agent
    # transcripts + token totals) to /outputs/<run_id>/ before the host can be
    # recreated and lose it. Best-effort; fires on every exit incl. review-gates
    # (so each phase boundary leaves a checkpoint; the final exit is complete).
    await _snapshot_opencode_db(run_id)
    # Merge this run's verifier-CONFIRMED findings into the engagement ledger.
    # Runs on EVERY exit (phase boundary, run end, watchdog/stall, graceful_finalize)
    # so a finalized-under-time-budget or aborted run still lands its CONFIRMED
    # verdicts. Best-effort + engagement-locked; never raises into the exit path.
    # GATED on verdict==CONFIRMED && ok_to_report==YES inside the helper — refuted /
    # inconclusive / NOT_A_VULN records are never merged. Re-runs de-duplicate by
    # canonical route+CWE key; existing engagement findings are preserved.
    try:
        _eng_id = _read_run_meta(run_id).get("engagement_id") or ""
        if _eng_id:
            async with _engagement_lock(_eng_id):
                _n = _merge_confirmed_findings_into_engagement(_eng_id, run_id)
            if _n:
                logger.info("lead_driver[%s] merged %d confirmed finding(s) into engagement %s",
                            run_id, _n, _eng_id)
    except Exception as exc:
        logger.warning("lead_driver[%s] confirmed-findings merge failed: %s", run_id, exc)

    # REC #17: MANDATORY reportwriter pass on run completion. Closes the gap
    # where reportwriter_input.json existed but no report.json/report.html was
    # ever produced (the pass only ran on explicit operator POST .../report/write
    # and silently skipped when the sandbox was down). Fire-and-forget so a slow
    # agent/fallback never blocks the driver exit or freezes sibling runs; the
    # startup sweep (_reconcile_all_engagement_reports) repairs anything this
    # misses after a restart. Idempotent: the age-comparison gate + atomic
    # overwrite make re-runs a no-op for unchanged findings.
    try:
        _meta = _read_run_meta(run_id) or {}
        _eid = _meta.get("engagement_id")
        if _eid:
            asyncio.create_task(_reconcile_reportwriter(_eid))
    except Exception:
        pass

    logger.info("lead_driver[%s] exited", run_id)

    # Container-busy guard: free the host so a new run can launch. Only clears the
    # slot if it still points at this run_id (a later launch on a different host
    # key is unaffected; a re-launch that somehow re-took this slot is preserved).
    try:
        _meta = _read_run_meta(run_id)
        _release_host_run(_meta.get("topology_id", ""),
                          _meta.get("host_id", ""), run_id)
    except Exception as _exc:
        logger.debug("lead_driver[%s] host-release skipped: %s", run_id, _exc)


@router.post("/runs/{run_id}/phases/{n}/advance")
async def advance_phase(run_id: str, n: int, req: AdvanceRequest) -> Dict[str, Any]:
    """Start phase `n` (typically current+1). Mark the currently-awaiting phase
    completed. `revised_objective` overrides phase n's objective (review &
    correct). Optionally flips the run phase_mode. Re-arms the driver."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found.")
    phases = meta.get("phases") or []
    rt = meta.get("phase_runtime") or []
    if not phases:
        raise HTTPException(status_code=409, detail="This run is not phased (legacy single-shot).")
    if not (0 <= n < len(phases)):
        raise HTTPException(status_code=400, detail=f"Phase index {n} out of range (0..{len(phases) - 1}).")

    if req.mode is not None:
        meta["phase_mode"] = req.mode.value

    # Mark the currently-awaiting phase completed (operator chose to move on).
    cur = meta.get("current_phase", -1)
    # Phase-0 hard guard (assessment Option A): glm-5.2 skipped Phase 0 on the
    # OpenHospital run (grabbed TARGET_IDENTITY| but emitted no THREAT_MODEL|).
    # Refuse to advance out of Phase 0 until engagement memory carries the
    # THREAT_MODEL| record (fallback TARGET_IDENTITY|). Best-effort nudge the
    # active Phase-0 session to finish scoping; the operator re-advances once it
    # has. Does NOT touch meta (phase 0 stays AWAITING_REVIEW) on refusal.
    if cur == 0 and not _phase0_complete(meta.get("engagement_id")):
        try:
            from ..services.container_addr import get_container_address
            from ..services.opencode_client import send_prompt_async, _ensure_network_connectivity
            await _ensure_network_connectivity(meta.get("container_id", ""))
            _addr = await get_container_address(meta.get("container_id", ""))
            _target = (rt[0].get("session_id") if rt else "") or meta.get("session_id", "")
            _agent = "coder56_phase" if (rt and rt[0].get("session_id")) else "coder56_lead"
            if _target:
                await send_prompt_async(
                    session_id=_target, host=_addr, port=4096, agent=_agent,
                    async_mode=True, timeout=30,
                    prompt=(
                        "Phase 0 is NOT complete — engagement memory has no THREAT_MODEL| record, so "
                        "the operator cannot advance to Phase 1. Finish Phase 0 NOW: append the "
                        "`THREAT_MODEL|app=…|jewels=…|sensitive_data=…|trust_boundaries=…|data_flows=…|"
                        "attacker_goals=…|risk_priorities=…|owasp_backstop=…` line (and TARGET_IDENTITY| "
                        "if missing) to engagement memory, then stop."
                    ),
                )
        except Exception as exc:
            logger.warning("phase0_guard[%s] nudge failed: %s", run_id, exc)
        raise HTTPException(
            status_code=409,
            detail="Phase 0 is incomplete: engagement memory has no THREAT_MODEL| record. Phase 0 "
                   "must emit THREAT_MODEL| (and TARGET_IDENTITY|) before deep testing. A corrective "
                   "prompt was sent to the Phase-0 worker; re-advance once it has.",
        )
    if 0 <= cur < len(rt) and rt[cur].get("status") == PhaseStatus.AWAITING_REVIEW.value:
        rt[cur]["status"] = PhaseStatus.COMPLETED.value
        meta["phase_runtime"] = rt
    _atomic_write(_run_meta_path(run_id), meta)

    from ..services.container_addr import get_container_address
    from ..services.opencode_client import _ensure_network_connectivity
    container_id = meta.get("container_id", "")
    await _ensure_network_connectivity(container_id)
    try:
        addr = await get_container_address(container_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not resolve container address: {exc}")
    orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
    if orch == Orchestration.NATIVE_SUBAGENTS.value:
        # The awaiting phase was marked completed above. Nudge the Lead to proceed
        # to phase n (spawn its coder56_phase subagent, record findings, then pace).
        # revised_objective, if given, steers the Lead's next subagent prompt.
        from ..services.opencode_client import send_prompt_async
        cont = (req.revised_objective or "").strip()
        msg = cont if cont else (
            f"Operator approved phase {n}. Proceed to phase {n + 1} now: spawn its coder56_phase "
            "subagent, record the findings, then follow the pacing rule."
        )
        await send_prompt_async(
            session_id=meta.get("session_id", ""), prompt=msg, host=addr, port=4096,
            agent="coder56_lead", async_mode=True, timeout=30,
        )
        _arm_lead_driver(run_id)
        return {"status": "running", "run_id": run_id, "phase": n, "session_id": meta.get("session_id", "")}
    session_id = await _start_phase(run_id, n, addr, revised_objective=req.revised_objective)
    _arm_driver(run_id)
    return {"status": "running", "run_id": run_id, "phase": n, "session_id": session_id}


class InterruptRequest(BaseModel):
    revised_objective: Optional[str] = None


@router.post("/runs/{run_id}/interrupt")
async def interrupt_run(run_id: str, req: InterruptRequest) -> Dict[str, Any]:
    """A6: cancel the in-flight phase turn and (optionally) restart the current
    phase with a revised objective. A native_subagents phase otherwise CANNOT be
    steered mid-turn — /guide drops a message the model is free to ignore
    (de1e6112: nemotron ignored two operator overrides for ~25 min and kept
    looping). This aborts the opencode session outright and starts a fresh one.
    Bumps interrupt_epoch so the driver treats the restart as a clean new phase
    (no stale phase_started_local → instant timeout)."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found.")
    rt = meta.get("phase_runtime") or []
    cur = meta.get("current_phase", -1)
    if not (0 <= cur < len(rt)):
        raise HTTPException(status_code=409, detail="Run has no active phase to interrupt.")
    container_id = meta.get("container_id", "")
    if not container_id:
        raise HTTPException(status_code=409, detail="No container for run.")
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import _ensure_network_connectivity, abort_session_async
    await _ensure_network_connectivity(container_id)
    addr = await get_container_address(container_id)

    entry = rt[cur]
    sess = entry.get("session_id", "")
    # 1) Abort the in-flight turn so the looping agent stops immediately.
    if sess:
        try:
            await abort_session_async(session_id=sess, host=addr, port=4096)
        except Exception as exc:
            logger.warning("interrupt[%s] abort of %s failed (continuing): %s", run_id, sess, exc)
    # 2) Mark the phase re-runnable + bump epoch so the driver re-tracks cleanly.
    entry["status"] = PhaseStatus.AWAITING_REVIEW.value
    entry["session_id"] = ""
    rt[cur] = entry
    meta["phase_runtime"] = rt
    meta["interrupt_epoch"] = int(meta.get("interrupt_epoch", 0)) + 1
    _atomic_write(_run_meta_path(run_id), meta)
    # 3) Restart the phase fresh (new session), optionally with a revised objective.
    new_sess = await _start_phase(run_id, cur, addr, revised_objective=req.revised_objective)
    _arm_driver(run_id)
    return {"status": "restarted", "run_id": run_id, "phase": cur,
            "session_id": new_sess, "revised_objective": bool((req.revised_objective or "").strip())}


@router.patch("/runs/{run_id}/phase-mode")
async def set_phase_mode(run_id: str, req: PhaseModeRequest) -> Dict[str, Any]:
    """Flip the run phase_mode mid-run. Switching to auto_continue while a non-last
    phase awaits review immediately advances it. Native-subagent runs also keep
    their driver armed so it can repair a stale REVIEW prompt at the next idle
    boundary when AUTO was selected after acceptance."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found.")
    meta["phase_mode"] = req.mode.value
    _atomic_write(_run_meta_path(run_id), meta)

    if req.mode == PhaseMode.AUTO_CONTINUE:
        native = meta.get("orchestration") == Orchestration.NATIVE_SUBAGENTS.value
        if native and meta.get("accepted_at"):
            # The Lead prompt is compiled once at accept time. If AUTO is chosen
            # afterwards, the live driver must explicitly override the stale
            # REVIEW pacing instruction when the current task returns.
            _arm_lead_driver(run_id)
        phases = meta.get("phases") or []
        rt = meta.get("phase_runtime") or []
        cur = meta.get("current_phase", -1)
        if 0 <= cur < len(rt) and rt[cur].get("status") == PhaseStatus.AWAITING_REVIEW.value and cur < len(phases) - 1:
            rt[cur]["status"] = PhaseStatus.COMPLETED.value
            meta["phase_runtime"] = rt
            _atomic_write(_run_meta_path(run_id), meta)
            from ..services.container_addr import get_container_address
            from ..services.opencode_client import _ensure_network_connectivity
            await _ensure_network_connectivity(meta.get("container_id", ""))
            try:
                addr = await get_container_address(meta.get("container_id", ""))
                if meta.get("orchestration") == Orchestration.NATIVE_SUBAGENTS.value:
                    # P2-6: native path — nudge the lead to spawn the next coder56_phase
                    # child. Never create a top-level coder56 session here (that was the
                    # session-per-phase degradation path).
                    from ..services.opencode_client import send_prompt_async
                    await send_prompt_async(
                        session_id=meta.get("session_id", ""),
                        prompt=(
                            "Runtime pacing is now AUTO_CONTINUE. This explicitly overrides any "
                            "earlier REVIEW/stop-at-boundary instruction. "
                            f"Operator approved phase {cur + 2}; proceed now: spawn its "
                            "coder56_phase subagent, record the findings, and continue all "
                            "remaining phases back-to-back without waiting for operator review."
                        ),
                        host=addr, port=4096, agent="coder56_lead", async_mode=True, timeout=30,
                    )
                    _arm_lead_driver(run_id)
                else:
                    await _start_phase(run_id, cur + 1, addr)
                    _arm_driver(run_id)
            except Exception as exc:
                logger.warning("phase-mode auto-advance for %s failed: %s", run_id, exc)
    return {"status": "ok", "run_id": run_id, "phase_mode": req.mode.value}


@router.post("/runs/{run_id}/phases/resume")
async def resume_phases(run_id: str) -> Dict[str, Any]:
    """Re-arm the driver for the current RUNNING phase (e.g. after a backend
    restart). State persists in run.json, so this only re-creates the poller."""
    _valid_token(run_id, "run_id")
    meta = _read_run_meta(run_id)
    if not meta:
        raise HTTPException(status_code=404, detail="No run manifest found.")
    if not (meta.get("phases") or []):
        raise HTTPException(status_code=409, detail="This run is not phased.")
    orch = meta.get("orchestration", Orchestration.BACKEND_SESSIONS.value)
    driver_map = _lead_drivers if orch == Orchestration.NATIVE_SUBAGENTS.value else _phase_drivers
    task = driver_map.get(run_id)
    if task and not task.done():
        return {"status": "already_running", "run_id": run_id}
    rt = meta.get("phase_runtime") or []
    cur = meta.get("current_phase", -1)
    # For native_subagents the Lead session is always "running" between advances,
    # so we only require a current phase index; for backend sessions the current
    # phase's session must actually be RUNNING.
    if orch == Orchestration.NATIVE_SUBAGENTS.value:
        if not (0 <= cur < len(rt)):
            return {"status": "nothing_to_resume", "run_id": run_id,
                    "detail": "no current phase — advance it instead"}
    elif not (0 <= cur < len(rt)) or rt[cur].get("status") != PhaseStatus.RUNNING.value:
        return {"status": "nothing_to_resume", "run_id": run_id,
                "detail": "current phase is not running — advance it instead"}
    if orch == Orchestration.NATIVE_SUBAGENTS.value:
        _arm_lead_driver(run_id)
    else:
        _arm_driver(run_id)
    return {"status": "resumed", "run_id": run_id, "current_phase": cur}


# =============================================================================
# Goal builder: compile + LLM draft
# =============================================================================

def _compile_directive(req: GoalCompileRequest) -> str:
    """Deterministically compile a structured engagement into the directive text
    that is sent to coder56 AND forwarded to the guardrail goal (single scope)."""
    lines: List[str] = []
    lines.append("=== AUTHORIZED ENGAGEMENT DIRECTIVE (sanctioned cyber-range exercise) ===")
    lines.append("")
    lines.append("OBJECTIVE:")
    lines.append(req.objective.strip() or "(no objective stated)")
    if req.target.strip():
        lines.append("")
        lines.append("AUTHORIZED SCOPE (target ONLY — all activity must stay within this):")
        lines.append(req.target.strip())
    if req.credentials.strip():
        lines.append("")
        lines.append("SEEDED CREDENTIALS (pre-existing OWNED credentials — authenticate with these; "
                     "never guess passwords or create accounts):")
        lines.append(req.credentials.strip())
    if req.rules_of_engagement.strip():
        lines.append("")
        lines.append("RULES OF ENGAGEMENT:")
        lines.append(req.rules_of_engagement.strip())
    if req.stop_conditions.strip():
        lines.append("")
        lines.append("STOP CONDITIONS:")
        lines.append(req.stop_conditions.strip())
    # C2: Phase 0 is always present and ALWAYS FIRST — threat-model + capture the
    # target identity before any testing. The `risk_priorities` it produces drive
    # risk-first ordering of the remaining phases.
    lines.append("")
    lines.append("PLANNED ENGAGEMENT CHAIN (MITRE ATT&CK phases):")
    lines.append("  Phase 0 — THREAT MODEL: build the threat model (crown jewels, sensitive-data "
                 "classes, trust boundaries, data flows, attacker goals, ordered risk_priorities) "
                 "and capture TARGET_IDENTITY; emit THREAT_MODEL|... and TARGET_IDENTITY|... to "
                 "shared memory. Generate the remaining phase order risk-first from risk_priorities.")
    if req.phases:
        for i, ph in enumerate(req.phases, 1):
            techs = ", ".join(ph.technique_ids) if ph.technique_ids else "(operator-defined)"
            lines.append(f"  Phase {i + 1} [{ph.tactic_id}] techniques({techs}): {ph.note.strip()}".rstrip())
            if ph.tools:
                lines.append(f"    Recommended tools: {', '.join(ph.tools)}")
            if ph.checklist:
                for item in ph.checklist:
                    lines.append(f"    [ ] {item}")
    lines.append("")
    lines.append("OPERATING RULES:")
    lines.append("- Confirm you are targeting ONLY the authorized scope above before any network action.")
    lines.append("- Prefer bounded, targeted commands; avoid mass-scanning or broad sweeps beyond scope.")
    lines.append("- Do NOT perform destructive impact, denial of service, or exfiltration to external systems outside the lab.")
    # C3: enumeration + multi-principal obligation; C8: non-mutating-first (the
    # read-only authz differential is the mandated first oracle).
    lines.append("- ENUMERATE the attack surface (SURFACE_ITEM| per endpoint x params x role x object_id) "
                 "and provision >=2 OWNED principals in different tenants/roles (PRINCIPAL|) using only "
                 "pre-existing owned/seeded credentials; never create accounts a no-mod RoE forbids.")
    lines.append("- Prove policy/RoE-sensitive findings with read-only oracles FIRST (registration-validation-error "
                 "introspection, client-side rule inspection, dup-key/expected-error differential); mutate state only "
                 "as a last resort, record it, and restore it.")
    lines.append("- Report findings concisely; iterate methodically phase by phase.")
    lines.append("=== END DIRECTIVE ===")
    return "\n".join(lines)


@router.post("/goal/compile", response_model=GoalDirective)
async def compile_goal(req: GoalCompileRequest) -> GoalDirective:
    directive = _compile_directive(req)
    summary = req.objective.strip()[:160] or "Scoped engagement directive"
    return GoalDirective(directive=directive, summary=summary)


# --- defensive JSON extraction (ported from guardrail.ts parseVerdict) ---

def _extract_json_fence(text: str) -> Optional[str]:
    m = re.search(r"```(?:json|JSON)?\s*([\s\S]*?)```", text)
    return m.group(1).strip() if m and m.group(1) else None


def _extract_first_json_object(text: str) -> Optional[str]:
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start:end + 1]
    return None


def _parse_loose_json(text: str) -> Optional[Dict[str, Any]]:
    for candidate in (_extract_json_fence(text), _extract_first_json_object(text)):
        if candidate:
            try:
                obj = json.loads(candidate)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                continue
    return None


_REFUSAL_MARKERS = ("i can't", "i cannot", "i'm not able", "i am not able",
                    "i won't", "i will not", "unable to", "as an ai",
                    "i don't assist", "cannot assist", "not appropriate")


def _looks_like_refusal(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _REFUSAL_MARKERS)


class LLMCallError(RuntimeError):
    """Raised by _llm_chat when raise_on_fail=True — carries the concrete reason
    (timeout / HTTP status / transport) so the caller can surface a real error
    instead of silently degrading to an empty result."""


async def _llm_chat(user_msg: str, system_msg: str, max_tokens: int = 16384,
                    timeout: float = LLM_CHAT_TIMEOUT_S, max_attempts: int = 2,
                    raise_on_fail: bool = False) -> Optional[str]:
    """Call the configured OpenAI-compatible LLM (same provider the agents use).

    By default returns assistant text or None on any failure (callers like
    /goal/draft fall back to a template). Pass raise_on_fail=True to instead
    raise LLMCallError with the reason — used by the findings draft, which must
    NOT silently drop a result when the model can't handle the full transcript.

    max_tokens defaults to 16384 because glm-5.2 is a THINKING model: its
    reasoning_tokens count against the SAME completion budget as the visible
    JSON (a measured goal-draft spent 9.2k tokens reasoning before ~3.1k of
    text). At the old 8192 cap every large draft was truncated mid-JSON
    (finish_reason=length) and silently degraded to the "not parseable JSON"
    template — the GoalBuilder then appeared to do nothing.

    Read timeouts are NEVER retried: a timeout on a large prompt means the model
    can't process the volume in time, and retrying just doubles the wait before
    the same failure. Transient HTTP errors (429 max_parallel_requests on the
    shared e-infra key, 5xx) and connection blips ARE retried."""
    base_url = os.getenv("LLM_URL", "").rstrip("/")
    api_key = os.getenv("OPENCODE_API_KEY", "")
    model = os.getenv("LLM_MODEL", "glm-5.2")
    if not base_url or not api_key:
        if raise_on_fail:
            raise LLMCallError("LLM not configured (LLM_URL / OPENCODE_API_KEY missing)")
        return None
    url = f"{base_url}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": user_msg},
        ],
        "max_tokens": max_tokens,
        "temperature": 0.4,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _fail(msg: str) -> Optional[str]:
        if raise_on_fail:
            raise LLMCallError(msg)
        return None

    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            # A timeout means the prompt is too large / model too slow — retrying
            # the same huge prompt won't help. Fail (fast) with a clear reason.
            logger.info("LLM read timeout after %ss (attempt %d/%d): %s", timeout, attempt, max_attempts, exc)
            return _fail(f"model read timeout after {timeout:.0f}s — the run transcript is too large for the model to process in one call ({len(user_msg)} chars)")
        except Exception as exc:
            # Connection / transport blip — transient, worth a retry.
            logger.info("LLM call failed (attempt %d/%d): %s: %s", attempt, max_attempts, type(exc).__name__, exc)
            if attempt < max_attempts:
                await asyncio.sleep(min(2.0 * attempt, 6.0))
                continue
            return _fail(f"LLM transport error: {type(exc).__name__}: {exc}")

        if resp.status_code == 200:
            try:
                data = resp.json()
            except Exception:
                logger.info("LLM returned non-JSON (attempt %d): %s", attempt, resp.text[:200])
                return _fail("LLM returned a non-JSON response")
            choices = data.get("choices") or []
            if choices and choices[0].get("finish_reason") == "length":
                # Truncated mid-output — for thinking models (glm-5.2) reasoning
                # shares the completion budget, so this means the visible text
                # (often strict JSON) got cut and WILL fail loose parsing.
                usage = data.get("usage") or {}
                logger.warning(
                    "LLM completion truncated (finish_reason=length, max_tokens=%d, "
                    "completion_tokens=%s) — output will likely fail JSON parsing",
                    max_tokens, usage.get("completion_tokens"),
                )
            return (choices[0].get("message", {}).get("content", "") if choices else "") or None

        # Transient (esp. 429 max_parallel_requests) -> back off and retry.
        if resp.status_code in _LLM_RETRY_STATUS and attempt < max_attempts:
            wait = _retry_after_seconds(resp, attempt)
            logger.info(
                "LLM HTTP %d (attempt %d/%d) — retrying in %.1fs",
                resp.status_code, attempt, max_attempts, wait,
            )
            await asyncio.sleep(wait)
            continue

        # Non-transient error (4xx auth/schema/context-length/etc.) or retries exhausted.
        logger.info(
            "LLM HTTP %d (attempt %d/%d), giving up: %s",
            resp.status_code, attempt, max_attempts, resp.text[:200],
        )
        return _fail(f"LLM HTTP {resp.status_code}: {resp.text[:200]}")
    return _fail("LLM call exhausted retries")


# HTTP statuses worth retrying: rate-limit + transient server/overload errors.
_LLM_RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}


def _retry_after_seconds(resp: httpx.Response, attempt: int) -> float:
    """Seconds to wait before a retry: honor a Retry-After header, else back off.

    Capped so a draft never stalls too long; the 429 (max_parallel_requests) clears
    as soon as an in-flight request finishes — usually within a second or two."""
    ra = resp.headers.get("Retry-After") if resp.headers else None
    if ra:
        try:
            return max(0.5, min(float(ra), 12.0))
        except (TypeError, ValueError):
            pass
    return min(2.0 * attempt, 8.0)



def _empty_draft() -> Dict[str, Any]:
    return {
        "objective": "",
        "target": "",
        "rules_of_engagement": "",
        "phases": [],
        "summary": "",
        "declined": True,
        # C2: threat model + risk priorities are first-class top-level fields so a
        # later phase can be risk-first. Empty by default; the planner populates them.
        "threat_model": {},
        "risk_priorities": [],
    }


# Representative HexStrike MCP tools available on coder56-mcp hosts. Surfaced to
# the phase drafter so it recommends the matching MCP tool (already available, no
# install) over a CLI the agent would have to install. ~130 more exist; the agent
# picks by name at runtime and falls back to bash when a tool is absent.
_HEXSTRIKE_MCP_TOOLS_NOTE = (
    "Hosts running the HexStrike MCP server (coder56-mcp hosts) already provide ~150 tools under "
    "the `hexstrike-ai_` prefix. Representative available tools: "
    "port/service scan: hexstrike-ai_nmap_scan, hexstrike-ai_nmap_advanced_scan, hexstrike-ai_masscan_high_speed, hexstrike-ai_rustscan_fast_scan; "
    "web/dir recon: hexstrike-ai_ffuf_scan, hexstrike-ai_gobuster_scan, hexstrike-ai_katana_crawl, hexstrike-ai_whatweb, hexstrike-ai_httpx_probe, hexstrike-ai_wafw00f_scan; "
    "web vuln: hexstrike-ai_nuclei_scan, hexstrike-ai_nikto_scan, hexstrike-ai_sqlmap_scan, hexstrike-ai_zap_scan, hexstrike-ai_dalfox_xss_scan; "
    "brute/crack: hexstrike-ai_hydra_attack, hexstrike-ai_john_crack, hexstrike-ai_hashcat_crack; "
    "enum/recon: hexstrike-ai_enum4linux_scan, hexstrike-ai_smbmap_scan, hexstrike-ai_dnsenum_scan, hexstrike-ai_amass_scan; "
    "binary/forensics: hexstrike-ai_radare2_analyze, hexstrike-ai_binwalk_analyze, hexstrike-ai_strings_extract, hexstrike-ai_volatility3_analyze."
)


async def _draft_goal_plan(objective: str, target: str, rules_of_engagement: str,
                           depth: str = "standard",
                           engagement_mode: EngagementMode = EngagementMode.NETWORK) -> Dict[str, Any]:
    """LLM-draft a scoped engagement plan (objective + MITRE phased chain) from a
    free-text objective. Shared by /goal/draft and the per-OWASP-category phase
    drafter. Always returns a valid (possibly empty-fielded) draft object — never
    throws. On refusal/failure returns declined:true with a template skeleton so
    the operator can fill it in.

    The planner frame is MODE-SELECTED: NETWORK (default, byte-for-byte no
    regression) keeps the threat-model + ATT&CK-label system prompt; API/WEBAPP
    switch to the OWASP WSTG v4.2 spine with the API Security Top-10 (2023) /
    Top-10 (2021) risk model, FORCE the web-app target filter (so host-compromise
    tactics cannot enter), and prepend a recon-first Phase R when the spec/roles/
    stack are not stated."""
    if engagement_mode == EngagementMode.API:
        system_msg = (
            "You are an authorized engagement planner for a SANCTIONED, ISOLATED cyber-range "
            "security exercise. The risk model for THIS engagement is the OWASP API Security "
            "Top-10 (2023) [API1-API10]; the testing spine is OWASP WSTG v4.2. Plan ONE phase per "
            "API category, RISK-FIRST: for a clinical/EHR system lead with API1 BOLA, API5 BFLA on "
            "writes, API3 mass-assignment, API6 business-logic. Every write-category phase MUST "
            "mandate cross-role PUT/DELETE/PATCH and capture the authorization differential across "
            ">=2 owned principals in DISTINCT role groups. OMIT host-compromise tactics (TA0004/6/8/"
            "10/11) — there is no host foothold to exercise them. If the OpenAPI/Swagger spec, role "
            "set, or tech stack is NOT explicitly stated in the objective, FIRST plan a recon-first "
            "Phase R (is_research_phase=true) that persists ground truth (OpenAPI spec path, endpoint "
            "inventory, tech stack, and one PRINCIPAL per role group with token_loc=<FILE path>) to "
            "/outputs/$RUN_ID/memory/MEMORY.md and is consumed as authoritative fact by every later "
            "phase. You always provide concrete planning for this authorized context."
        )
        _label_line = (
            "Use OWASP API category ids (API1-API10) as the phase label; ORDER PHASES RISK-FIRST "
            "(API1/API5/API3/API6 first). Each phase MUST include a `tools` array with 2-4 recommended "
            "tools and a `checklist` array listing 3-6 concrete goals. Keep scope tight to the stated "
            "target. No commentary outside the JSON."
        )
    elif engagement_mode == EngagementMode.WEBAPP:
        system_msg = (
            "You are an authorized engagement planner for a SANCTIONED, ISOLATED cyber-range "
            "security exercise. The risk model for THIS engagement is the OWASP Top-10 (2021) "
            "[A01-A10]; the testing spine is OWASP WSTG v4.2. Plan application-layer phases — "
            "authentication, authorization/role matrix, injection, session/secrets, business logic, "
            "data exposure — and OMIT host-compromise phases (privilege escalation, host credential "
            "extraction, lateral movement, exfiltration, C2; ATT&CK TA0004/6/8/10/11) that cannot "
            "apply without a host foothold. If the attack surface, role set, or tech stack is NOT "
            "explicitly stated, FIRST plan a recon-first Phase R (is_research_phase=true) that "
            "persists ground truth to /outputs/$RUN_ID/memory/MEMORY.md and is consumed as "
            "authoritative fact by every later phase. You always provide concrete planning for this "
            "authorized context."
        )
        _label_line = (
            "Use OWASP category ids (A01-A10) as the phase label; ORDER PHASES RISK-FIRST (A01/A03/"
            "A07 first). Each phase MUST include a `tools` array with 2-4 recommended tools and a "
            "`checklist` array listing 3-6 concrete goals. Keep scope tight to the stated target. "
            "No commentary outside the JSON."
        )
    else:
        system_msg = (
            "You are an authorized engagement planner for a SANCTIONED, ISOLATED cyber-range "
            "security exercise. You help a red-team operator structure a scoped, rules-bound "
            "engagement plan aligned to the MITRE ATT&CK kill chain. You always provide concrete "
            "planning for this authorized context."
        )
        _label_line = (
            "Use real ATT&CK tactic IDs (TA0043 Recon, TA0001 Initial Access, TA0002 Execution, "
            "TA0003 Persistence, TA0004 Privilege Escalation, TA0005 Defense Evasion, TA0006 "
            "Credential Access, TA0007 Discovery, TA0008 Lateral Movement, TA0009 Collection, "
            "TA0011 Command and Control, TA0010 Exfiltration) and technique IDs. Keep scope tight "
            "to the stated target. No commentary outside the JSON."
        )
    user_msg = (
        f"Draft a scoped engagement plan for this authorized objective:\n\"\"\"\n{objective.strip()}\n\"\"\"\n"
        + (f"\nAuthorized target/scope: {target.strip()}\n" if target.strip() else "")
        + (f"\nRules of engagement: {rules_of_engagement.strip()}\n" if rules_of_engagement.strip() else "")
        + f"\nDepth: {depth}.\n\n"
        "Return ONLY a JSON object with this exact shape:\n"
        '{"objective":"<refined one-line objective>","target":"<CIDR/host, scoped tight>","rules_of_engagement":"<RoE: allowed/denied, no DoS, lab-only>",'
        '"phases":[{"tactic_id":"TAxxxx","name":"<tactic>","technique_ids":["Txxxx"],"note":"<one-line phase goal>",'
        '"tools":["<recommended tool 1>","<tool 2>",...],"checklist":["<task 1>","<task 2>",...]}],'
        '"threat_model":{"jewels":"<crown-jewel assets>","sensitive_data":"<data classes>",'
        '"trust_boundaries":"<comma-sep>","attacker_goals":"<comma-sep>"},'
        '"risk_priorities":["<vuln-class hypothesis 1, highest priority>","<hypothesis 2>",...],'
        '"summary":"<2-3 sentence plan summary>"}\n'
        "risk_priorities is an ORDERED list (highest risk first) of vuln-class hypotheses derived from the "
        "threat model; subsequent phases should be ordered to test risk_priorities[0] first. "
        "Each phase MUST include a `tools` array with 2-4 recommended tools for that phase's objective, "
        "and a `checklist` array listing 3-6 concrete goals or tasks the agent should verify/complete in that phase. "
        "CLARIFY each tool's source/availability: PREFER a tool ALREADY AVAILABLE via the HexStrike MCP server — "
        "list it by its `hexstrike-ai_*` name (no install needed, auto-adjudicated by the guardrail); only list a "
        "BARE CLI name (e.g. nmap, sqlmap, ffuf, hydra, john, hashcat, ldapsearch, metasploit, impacket, certipy, "
        "enum4linux, evil-winrm, bloodhound, chisel, ligolo-ng, curl, netcat) when NO hexstrike-ai_* tool covers the "
        "task AND the agent must install it. The naming is the signal: a `hexstrike-ai_*` entry means 'use the "
        "available MCP tool'; a bare name means 'install this CLI'. "
        + _HEXSTRIKE_MCP_TOOLS_NOTE
        + " "
        + _label_line
    )

    text = await _llm_chat(user_msg, system_msg)
    if not text or _looks_like_refusal(text):
        d = _empty_draft()
        d["objective"] = objective.strip()
        d["target"] = target.strip()
        d["rules_of_engagement"] = rules_of_engagement.strip()
        d["summary"] = "LLM declined or was unavailable; showing a template for you to fill in."
        return d

    obj = _parse_loose_json(text)
    if not obj:
        d = _empty_draft()
        d["objective"] = objective.strip()
        d["target"] = target.strip()
        d["rules_of_engagement"] = rules_of_engagement.strip()
        d["summary"] = "LLM response was not parseable JSON; showing a template."
        return d

    obj.setdefault("objective", objective.strip())
    obj.setdefault("target", target.strip())
    obj.setdefault("rules_of_engagement", rules_of_engagement.strip())
    obj.setdefault("phases", [])
    if engagement_mode in (EngagementMode.API, EngagementMode.WEBAPP):
        # Mode-selected: a Phase R is prepended when the spec/roles/stack are not
        # stated, and the web-app target filter is FORCED (never inferred) so no
        # host-compromise tactic (TA0004/6/8/10/11) can enter the plan even if the
        # model regresses to a kill chain — the de1e6112 6-of-9-unreachable failure
        # mode becomes structurally impossible.
        obj = _ensure_research_phase_if_needed(obj, target, rules_of_engagement)
        obj["phases"] = _filter_phases_for_target(obj.get("phases") or [], "web")
    else:
        # A1: drop host-compromise phases that can't apply to a web/API target.
        obj["phases"] = _filter_phases_for_target(
            obj.get("phases") or [], _infer_target_class(target, rules_of_engagement))
    obj.setdefault("summary", "")
    # C2: guarantee the threat-model + risk-priorities keys exist even if the model
    # omits them (callers read them unconditionally to drive risk-first ordering).
    obj.setdefault("threat_model", {})
    obj.setdefault("risk_priorities", [])
    obj["declined"] = False
    return obj


@router.post("/goal/draft")
async def draft_goal(req: GoalDraftRequest) -> Dict[str, Any]:
    """Ask the LLM to draft a scoped engagement chain + RoE from the objective.
    Thin wrapper over _draft_goal_plan (shared with the OWASP phase drafter).
    Threads req.engagement_mode so the planner frame is operator-selected
    (NETWORK default = byte-for-byte no regression; API/WEBAPP = WSTG spine)."""
    return await _draft_goal_plan(
        req.objective, req.target, req.rules_of_engagement, req.depth,
        engagement_mode=req.engagement_mode or EngagementMode.NETWORK,
    )


# =============================================================================
# Engagements (CRUD + run linking)
# =============================================================================

def _public(eng: Dict[str, Any]) -> Dict[str, Any]:
    """Engagement dict with findings sorted for display (does not mutate input)."""
    e = dict(eng)
    e["findings"] = _sort_findings(e.get("findings") or [])
    return e


@router.post("/engagements")
async def create_engagement(req: EngagementCreate) -> Dict[str, Any]:
    eid = _new_id()
    now = _now_iso()
    eng: Dict[str, Any] = {
        **req.dict(),
        "id": eid,
        "created_at": now,
        "updated_at": now,
        "run_ids": [],
        "findings": [],
    }
    _write_engagement(eid, eng)
    return {"engagement": _public(eng)}


@router.get("/engagements")
async def list_engagements() -> Dict[str, Any]:
    return {"engagements": [_public(e) for e in _load_all_engagements()]}


@router.get("/engagements/{engagement_id}")
async def get_engagement(engagement_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    eng = await _reconcile_planned_run_statuses(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return _engagement_detail(eng)


@router.get("/engagements/{engagement_id}/metrics")
async def get_engagement_metrics(engagement_id: str) -> Dict[str, Any]:
    """Return auditable execution cost, elapsed time, and finding efficiency.

    opencode.db snapshots are container-global and cumulative. The metrics
    service de-duplicates logical sessions across all linked snapshots before
    attributing them to this engagement's run roots.
    """
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return build_engagement_metrics(OUTPUTS_DIR, eng)


@router.patch("/engagements/{engagement_id}")
async def update_engagement(engagement_id: str, req: EngagementUpdate) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    for k, v in req.dict(exclude_unset=True).items():
        if v is not None:
            eng[k] = v
    eng["updated_at"] = _now_iso()
    _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng)}


@router.delete("/engagements/{engagement_id}")
async def delete_engagement(engagement_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    path = _engagement_path(engagement_id)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Best-effort: clear the engagement_id link on each run manifest so stale
    # links don't dangle. The run data itself is never touched.
    eng = _read_engagement(engagement_id) or {}
    for rid in eng.get("run_ids", []) or []:
        meta = _read_run_meta(rid)
        if meta and meta.get("engagement_id") == engagement_id:
            meta["engagement_id"] = None
            try:
                _atomic_write(_run_meta_path(rid), meta)
            except Exception:
                pass
    path.unlink(missing_ok=True)
    return {"status": "deleted", "engagement_id": engagement_id}


@router.post("/engagements/{engagement_id}/runs")
async def link_run(engagement_id: str, req: AddRunRequest) -> Dict[str, Any]:
    """Link an existing run to the engagement. Idempotent. Also writes
    engagement_id into the run manifest so the legacy /run/:runId redirect
    resolves in O(1)."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(req.run_id, "run_id")
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id)
        if not eng:
            raise HTTPException(status_code=404, detail="Engagement not found")
        if req.run_id not in (eng.get("run_ids") or []):
            eng["run_ids"] = (eng.get("run_ids") or []) + [req.run_id]
        eng["updated_at"] = _now_iso()
        _write_engagement(engagement_id, eng)
    # Additive manifest link (merge so we don't clobber existing fields).
    meta = _read_run_meta(req.run_id)
    if meta is not None:
        meta["engagement_id"] = engagement_id
        try:
            _atomic_write(_run_meta_path(req.run_id), meta)
        except Exception:
            pass
    return {"engagement": _public(eng)}


@router.delete("/engagements/{engagement_id}/runs/{run_id}")
async def unlink_run(engagement_id: str, run_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    _valid_token(run_id, "run_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    eng["run_ids"] = [r for r in (eng.get("run_ids") or []) if r != run_id]
    eng["updated_at"] = _now_iso()
    _write_engagement(engagement_id, eng)
    meta = _read_run_meta(run_id)
    if meta and meta.get("engagement_id") == engagement_id:
        meta["engagement_id"] = None
        try:
            _atomic_write(_run_meta_path(run_id), meta)
        except Exception:
            pass
    return {"engagement": _public(eng)}


# =============================================================================
# OWASP Top 10 plan (drafted per-category runs; "draft 10, run one at a time")
#
# A plan is a list of PlannedRun drafts (one per OWASP A01-A10), generated
# deterministically from the catalog + the engagement's scope+target. Each draft
# is materialized into a REAL run on demand via the existing launch() path — the
# agent stays idle until /runs/{run_id}/accept (the human-in-the-loop gate).
# =============================================================================

def _compile_owasp_directive(pr: Dict[str, Any], eng: Dict[str, Any]) -> str:
    """Compile one OWASP planned-run into the directive text sent to coder56 AND
    forwarded to the guardrail goal (single scope). Mirrors _compile_directive's
    wording but bakes the OWASP category focus + the WSTG checklist + tools in as
    the agent's structured test plan (single-shot, no phases)."""
    target = (eng.get("target_scope") or "").strip()
    obj = (pr.get("objective") or "").strip() or (
        f"Assess {target or 'the engagement target'} for {pr.get('title','')} "
        f"(OWASP {pr.get('owasp_id','')}) flaws."
    )
    lines: List[str] = []
    lines.append("=== AUTHORIZED ENGAGEMENT DIRECTIVE (sanctioned cyber-range exercise) ===")
    lines.append("")
    lines.append("OBJECTIVE:")
    lines.append(obj)
    if target:
        lines.append("")
        lines.append("AUTHORIZED SCOPE (target ONLY — all activity must stay within this):")
        lines.append(target)
    creds = (eng.get("credentials") or "").strip()
    if creds:
        lines.append("")
        lines.append("SEEDED CREDENTIALS (pre-existing OWNED credentials — authenticate with these; "
                     "never guess passwords or create accounts):")
        lines.append(creds)
    roe = (eng.get("roe") or "").strip()
    if roe:
        lines.append("")
        lines.append("RULES OF ENGAGEMENT:")
        lines.append(roe)
    lines.append("")
    lines.append(f"FOCUS: OWASP Top 10 {pr.get('owasp_id','')} — {pr.get('title','')}")
    # C2: even the single-shot OWASP path threat-models FIRST. Phase 0 produces the
    # risk_priorities that re-order the checklist below (risk-first), and captures the
    # TARGET_IDENTITY so a repointed host is detected.
    lines.append("PHASE 0 — THREAT MODEL (do this first): build the threat model (crown jewels, "
                 "sensitive-data classes, trust boundaries, data flows, attacker goals, ordered "
                 "risk_priorities) and capture TARGET_IDENTITY; emit THREAT_MODEL|... and "
                 "TARGET_IDENTITY|... to shared memory. Then enumerate the attack surface "
                 "(SURFACE_ITEM|) and provision >=2 OWNED principals in different tenants/roles (PRINCIPAL|).")
    checklist = pr.get("checklist") or []
    if checklist:
        lines.append("STRUCTURED TEST PLAN (work RISK-FIRST — highest risk_priorities first; "
                     "prove each with evidence):")
        for item in checklist:
            lines.append(f"  [ ] {item}")
    tools = pr.get("tools") or []
    if tools:
        lines.append(f"Recommended tools: {', '.join(tools)}")
    notes = (pr.get("scope_notes") or "").strip()
    if notes:
        lines.append("")
        lines.append("SCOPE NOTES:")
        lines.append(notes.replace("{target}", target or "the authorized target").strip())
    # C7: surface STOP CONDITIONS (the single-shot path previously dropped them).
    # A category's objective is met when every surface item relevant to this CWE
    # class is terminal (TESTED confirmed/negative); emit `CATEGORY OBJECTIVE MET`.
    lines.append("")
    lines.append("STOP CONDITIONS:")
    lines.append(f"- The OWASP {pr.get('owasp_id','')} category objective is MET when every enumerated "
                 "surface item of this CWE class is terminal: a CONFIRMED finding with one bounded "
                 "impact proof, OR a documented negative across the relevant sinks/roles.")
    lines.append(f"- On met, emit `CATEGORY OBJECTIVE MET ({pr.get('owasp_id','')}) — <which surface "
                 "items / evidence>` and STOP this category rather than grinding leftover phases. Do "
                 "NOT re-test a surface item already [TESTED]/[NEGATIVE] in shared memory.")
    lines.append("")
    lines.append("OPERATING RULES:")
    lines.append("- Confirm you are targeting ONLY the authorized scope above before any network action.")
    lines.append("- Prefer bounded, targeted commands; avoid mass-scanning or broad sweeps beyond scope.")
    lines.append("- Do NOT perform destructive impact, denial of service, or exfiltration to external systems outside the lab.")
    lines.append("- Report findings concisely with concrete evidence (request/response, exact commands).")
    lines.append("=== END DIRECTIVE ===")
    return "\n".join(lines)


@router.post("/engagements/{engagement_id}/owasp-plan")
async def draft_owasp_plan(engagement_id: str, req: OwaspPlanRequest) -> Dict[str, Any]:
    """Generate (or regenerate) the OWASP Top 10 plan for an engagement from one
    shared scope+target. Produces 10 drafted PlannedRuns (A01-A10) from the
    catalog — deterministic, no LLM call — and stores the 'where coder56 runs'
    defaults (plan_launch) applied when a planned run is later materialized."""
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    target = (req.target_scope if req.target_scope is not None else (eng.get("target_scope") or "")).strip()
    if not target:
        # Never produce 10 blank runs: fall back to the engagement name; the
        # operator should set a real scope before running any.
        target = (eng.get("name") or "the engagement target").strip()
    eng_prefix = (req.objective if req.objective is not None else (eng.get("objective") or "")).strip()
    # Mode-selected catalog (forward-compatible): NETWORK/WEBAPP use the OWASP
    # Top-10 (2021) web catalog; API uses the OWASP API Security Top-10 (2023)
    # catalog (api_security_catalog.py). engagement_mode is read defensively so the
    # current OwaspPlanRequest (no field yet) stays byte-for-byte on owasp_catalog;
    # a future request field selects the API catalog without changing this handler.
    _plan_mode = getattr(req, "engagement_mode", None) or EngagementMode.NETWORK
    _catalog = (api_security_catalog() if _plan_mode == EngagementMode.API else owasp_catalog())
    plan: List[Dict[str, Any]] = []
    for cat in _catalog["categories"]:
        tmpl = cat.get("objective_template", "") or ""
        try:
            obj = tmpl.format(target=target)
        except Exception:
            obj = tmpl.replace("{target}", target)
        if eng_prefix:
            obj = f"{eng_prefix}\n\n{obj}"
        plan.append(PlannedRun(
            owasp_id=cat["id"],
            title=cat.get("name", ""),
            objective=obj,
            checklist=list(cat.get("checklist", [])),
            tools=list(cat.get("tools", [])),
            scope_notes=cat.get("scope_notes", ""),
            assessable=cat.get("assessable", "black-box"),
            status=PlannedRunStatus.PLANNED,
        ).dict())
    eng["plan"] = plan
    eng["plan_launch"] = {
        "topology_id": req.topology_id,
        "host_id": req.host_id,
        "isolated": bool(req.isolated),
        "criticality": req.criticality.value,
    }
    eng["updated_at"] = _now_iso()
    _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng)}


@router.post("/engagements/{engagement_id}/plan/{owasp_id}/draft-phases")
async def draft_planned_run_phases(engagement_id: str, owasp_id: str, req: PlannedPhaseDraftRequest) -> Dict[str, Any]:
    """LLM-draft a phased execution plan for ONE OWASP category (the same
    goal/draft planner normal runs use), scoped to the engagement target. Stores
    the drafted phases on the PlannedRun so the operator can review/edit them in
    the Plan tab before running. Structurally always succeeds; on LLM
    refusal/failure it stores empty phases + an explanatory note."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(owasp_id, "owasp_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    plan = eng.get("plan") or []
    pr = next((p for p in plan if p.get("owasp_id") == owasp_id), None)
    if pr is None:
        raise HTTPException(status_code=404, detail=f"No planned run for {owasp_id} in this engagement")

    target = (eng.get("target_scope") or "").strip()
    roe = (eng.get("roe") or "").strip()
    objective = (pr.get("objective") or "").strip()
    # Reinforce the OWASP focus so the planner tailors the kill-chain to it.
    focus_obj = f"[OWASP Top 10 {owasp_id} — {pr.get('title', '')}] {objective}".strip()

    # Mode-selected planner frame (forward-compatible): the OWASP-plan path
    # defaults to NETWORK (the web Top-10 catalog); API mode is selected only if
    # the request carries engagement_mode=API. Read defensively so the current
    # PlannedPhaseDraftRequest (no field yet) stays byte-for-byte unchanged.
    _plan_mode = getattr(req, "engagement_mode", None) or EngagementMode.NETWORK
    draft = await _draft_goal_plan(
        objective=focus_obj, target=target, rules_of_engagement=roe, depth=req.depth,
        engagement_mode=_plan_mode,
    )
    phases: List[Dict[str, Any]] = []
    for ph in draft.get("phases") or []:
        phases.append({
            "objective": (ph.get("note") or ph.get("name") or "").strip(),
            "tactic_id": ph.get("tactic_id") or "TA0043",
            "technique_ids": list(ph.get("technique_ids") or []),
            "note": ph.get("note", ""),
            "tools": list(ph.get("tools") or []),
            "checklist": list(ph.get("checklist") or []),
        })
    phase_draft_note = (draft.get("summary") or "").strip()

    # Re-read under the engagement lock before writing. The snapshot read at the
    # top of this handler can be stale by the time we write: _draft_goal_plan is a
    # long LLM call (often 60s+, sometimes a 600s timeout + retry) that may straddle
    # a concurrent plan/{owasp_id}/run registering its run_id. Writing the stale
    # snapshot clobbers that registration (orphaning the run). Mirrors run_planned_run.
    async with _engagement_lock(engagement_id):
        latest = _read_engagement(engagement_id)
        if not latest:
            raise HTTPException(status_code=404, detail="Engagement not found")
        latest_pr = next(
            (p for p in (latest.get("plan") or []) if p.get("owasp_id") == owasp_id),
            None,
        )
        if latest_pr is None:
            raise HTTPException(status_code=409, detail=f"Planned run {owasp_id} disappeared during draft")
        latest_pr["phases"] = phases
        latest_pr["phase_draft_note"] = phase_draft_note
        latest["updated_at"] = _now_iso()
        _write_engagement(engagement_id, latest)
    return {"engagement": _public(latest), "declined": bool(draft.get("declined"))}


@router.post("/engagements/{engagement_id}/plan/{owasp_id}/run")
async def run_planned_run(engagement_id: str, owasp_id: str) -> Dict[str, Any]:
    """Materialize ONE drafted planned run into a real coder56 run (launch), then
    land on the accept gate. If the operator drafted phases (LLM), this is a
    PHASED native_subagents run — just like a normal run; otherwise it falls back
    to a single phase built from the category checklist. Reuses the existing
    launch() path (topology/host OR isolated sandbox from plan_launch). The agent
    stays idle until /runs/{run_id}/accept."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(owasp_id, "owasp_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    plan = eng.get("plan") or []
    pr = next((p for p in plan if p.get("owasp_id") == owasp_id), None)
    if pr is None:
        raise HTTPException(status_code=404, detail=f"No planned run for {owasp_id} in this engagement")

    pl = eng.get("plan_launch") or {}
    isolated = bool(pl.get("isolated"))
    topology_id = pl.get("topology_id")
    host_id = pl.get("host_id")
    if not isolated and not (topology_id and host_id):
        raise HTTPException(
            status_code=409,
            detail="No launch target set for this engagement's OWASP plan. Re-draft the plan with a topology/host, or enable isolated.",
        )
    try:
        criticality = Criticality(pl.get("criticality") or "medium")
    except ValueError:
        criticality = Criticality.MEDIUM

    target_scope = (eng.get("target_scope") or "").strip()
    roe = (eng.get("roe") or "").strip()
    category_obj = (pr.get("objective") or "").strip() or (
        f"Assess {target_scope} for {pr.get('title', '')} (OWASP {owasp_id})")

    # C7: a real, category-specific STOP CONDITIONS predicate (previously dropped —
    # the single-shot path passed stop_conditions=""). The authoritative signal is a
    # CONFIRMED verdict of this category; the predicate is advisory.
    stop_conditions = (
        f"OWASP {owasp_id} objective is MET when every enumerated surface item of this CWE class is "
        f"terminal: a CONFIRMED finding with one bounded impact proof, OR a documented negative across "
        f"the relevant sinks/roles. On met, emit `CATEGORY OBJECTIVE MET ({owasp_id}) — <evidence>` and STOP."
    )

    # Drafted phases present => phased native_subagents run (the normal-run path).
    drafted = [p for p in (pr.get("phases") or []) if (p.get("objective") or p.get("note") or "").strip()]
    if drafted:
        phase_specs = _dedup_phase_plan([PhaseSpec(
            objective=(p.get("objective") or p.get("note") or "").strip(),
            tactic_id=p.get("tactic_id") or "TA0043",
            technique_ids=list(p.get("technique_ids") or []),
            note=p.get("note", ""),
            tools=list(p.get("tools") or []),
            checklist=list(p.get("checklist") or []),
        ) for p in drafted])
        mitre_phases = [MitrePhaseSelection(
            tactic_id=p.tactic_id, technique_ids=p.technique_ids,
            note=p.objective or p.note, tools=p.tools, checklist=p.checklist,
        ) for p in phase_specs]
        directive = _compile_directive(GoalCompileRequest(
            objective=category_obj, target=target_scope, rules_of_engagement=roe,
            phases=mitre_phases, stop_conditions=stop_conditions,
        ))
    else:
        # Fallback (no LLM draft yet): prepend a synthetic Phase-0 PhaseSpec so even
        # the checklist-fallback run threat-models + captures TARGET_IDENTITY first
        # (C2). The checklist phase follows.
        phase0 = PhaseSpec(
            objective=(
                "Phase 0 — build threat model (crown jewels, data classes, trust boundaries, attacker "
                "goals) and capture TARGET_IDENTITY; emit THREAT_MODEL|... to memory"
            ),
            tactic_id="TA0043", technique_ids=[], note="Phase 0 threat model",
            tools=[], checklist=[],
        )
        phase_specs = [phase0, PhaseSpec(
            objective=category_obj, tactic_id="TA0043", technique_ids=[],
            note=category_obj, tools=list(pr.get("tools") or []),
            checklist=list(pr.get("checklist") or []),
        )]
        directive = _compile_owasp_directive(pr, eng)

    launch_req = LaunchRequest(
        topology_id=topology_id if not isolated else None,
        host_id=host_id if not isolated else None,
        isolated=isolated,
        criticality=criticality,
        directive=directive,
        engagement_id=engagement_id,
        phases=phase_specs,
        phase_mode=PhaseMode.REVIEW_EACH,
        orchestration=Orchestration.NATIVE_SUBAGENTS,
    )
    resp = await launch(launch_req)  # prepares the run; agent idle until /accept

    # Record the materialized run on the latest ledger, not the stale snapshot
    # read before launch.  Concurrent category launches may both spend minutes in
    # launch(); serializing and re-reading here preserves both statuses/run ids.
    async with _engagement_lock(engagement_id):
        latest = _read_engagement(engagement_id)
        if not latest:
            raise HTTPException(status_code=404, detail="Engagement disappeared during launch")
        latest_pr = next(
            (p for p in (latest.get("plan") or []) if p.get("owasp_id") == owasp_id),
            None,
        )
        if latest_pr is None:
            raise HTTPException(status_code=409, detail=f"Planned run {owasp_id} disappeared during launch")
        latest_pr["run_id"] = resp.run_id
        latest_pr["run_at"] = _now_iso()
        latest_pr["status"] = PlannedRunStatus.RUNNING.value
        latest["updated_at"] = _now_iso()
        _write_engagement(engagement_id, latest)
    return {"run_id": resp.run_id, "owasp_id": owasp_id, "engagement_id": engagement_id}


@router.patch("/engagements/{engagement_id}/plan/{owasp_id}")
async def update_planned_run(engagement_id: str, owasp_id: str, req: PlannedRunUpdate) -> Dict[str, Any]:
    """Update a drafted planned run — mark it DONE/SKIPPED after assessing, or
    tweak the templated objective before running."""
    _valid_token(engagement_id, "engagement_id")
    _valid_token(owasp_id, "owasp_id")
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id)
        if not eng:
            raise HTTPException(status_code=404, detail="Engagement not found")
        plan = eng.get("plan") or []
        pr = next((p for p in plan if p.get("owasp_id") == owasp_id), None)
        if pr is None:
            raise HTTPException(status_code=404, detail=f"No planned run for {owasp_id} in this engagement")
        if req.status is not None:
            pr["status"] = req.status.value
            # "planned" means no materialized execution is currently associated
            # with this category. Keeping the prior collision id made a planned
            # row look like a third live/completed run.
            if req.status == PlannedRunStatus.PLANNED:
                pr["run_id"] = None
                pr["run_at"] = ""
        if req.objective is not None:
            pr["objective"] = req.objective
        if req.phases is not None:
            pr["phases"] = [p.dict() for p in req.phases]
        eng["updated_at"] = _now_iso()
        _write_engagement(engagement_id, eng)
    return {"engagement": _public(eng)}


# =============================================================================
# Findings (curated; stored inside the engagement JSON)
# =============================================================================

def _add_finding(eng: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    eng.setdefault("findings", []).append(finding)
    eng["updated_at"] = _now_iso()
    return eng


def _merge_confirmed_findings_into_engagement(engagement_id: str, run_id: str) -> int:
    """Merge this run's verifier-CONFIRMED findings into the engagement ledger.

    Scans /outputs/<run_id>/verifier/*.jsonl (via _extract_verifier_findings, which
    parses line-by-line — skipping malformed lines, never whole-file — and sets
    verified=True ONLY when the VERDICT record has verdict=="CONFIRMED" OR
    ok_to_report=="YES"). NOT_A_VULN / INCONCLUSIVE / NOT_CONFIRMABLE are never
    merged. New CONFIRMED findings are appended to engagement.findings[]; existing
    findings are PRESERVED (never overwritten) and de-duplicated by canonical key
    (route + CWE, via _dedup_key) so re-runs don't duplicate. Returns the number of
    NEW findings appended. Holds the engagement lock for the read-merge-write so a
    concurrent run registration cannot clobber it (see _draft_phases_clobbers_run_ledger).
    """
    if not engagement_id or not run_id:
        return 0
    try:
        candidates = _extract_verifier_findings(run_id)
    except Exception as exc:
        logger.warning("merge_confirmed_findings[%s] extract failed: %s", run_id, exc)
        return 0
    # Gate strictly on verifier CONFIRMED (defensive: _extract_verifier_findings
    # already sets verified only on CONFIRMED/ok_to_report==YES, but we re-check so
    # a future change to that helper cannot leak refuted/inconclusive records in).
    candidates = [f for f in candidates if f.get("verified") is True]
    # f6182182 "2/9" defect: recon-level misconfigurations (the agent's M-NNN
    # table in final_report.md) never pass the verifier gate, so they were
    # silently dropped here and the client deliverable under-reported. Append
    # them with HONEST provenance (verified=false, severity capped at LOW by
    # _extract_recon_findings); _dedup_key keeps re-runs idempotent.
    try:
        recon = _extract_recon_findings(run_id)
    except Exception as exc:
        logger.warning("merge_confirmed_findings[%s] recon extract failed: %s", run_id, exc)
        recon = []
    if recon:
        logger.info("merge_confirmed_findings[%s] adding %d recon-level finding(s)",
                    run_id, len(recon))
    candidates = candidates + recon
    if not candidates:
        return 0

    eng = _read_engagement(engagement_id)
    if not eng:
        return 0

    # OWASP plan mapping so a merged finding carries its category (mirrors
    # _draft_findings_inprocess).
    plan = eng.get("plan") or []
    run_to_owasp = {p.get("run_id"): (p.get("owasp_id"), p.get("title"))
                    for p in plan if p.get("run_id")}
    oid, _otitle = run_to_owasp.get(run_id, ("", ""))

    existing = eng.get("findings") or []
    existing_keys = set()
    for f in existing:
        try:
            existing_keys.add(_dedup_key(f))
        except Exception:
            existing_keys.add(str(f.get("title", "")).lower()[:60])

    now = _now_iso()
    added = 0
    new_findings = list(existing)
    seen_new: set = set()
    for cand in candidates:
        cand = dict(cand)
        cand["discovered_via_run_id"] = run_id
        if oid:
            cand["owasp_id"] = oid
        try:
            key = _dedup_key(cand)
        except Exception:
            key = str(cand.get("title", "")).lower()[:60]
        # Skip if already in the engagement (preserve existing) OR already added
        # this run (two CONFIRMED VERDICTs for the same issue).
        if key in existing_keys or key in seen_new:
            continue
        seen_new.add(key)
        # CVSS fallback: _extract_verifier_findings already copies the recomputed
        # CVSS from the VERDICT record into cand["cvss"], so no extra fallback is
        # needed; we just carry it through.
        finding = {
            "title": str(cand.get("title") or "")[:200],
            "severity": str(cand.get("severity") or "medium").lower(),
            "cvss": cand.get("cvss"),
            "affected_asset": str(cand.get("affected_asset") or "")[:300],
            "description": str(cand.get("description") or ""),
            "impact": str(cand.get("impact") or ""),
            "evidence": str(cand.get("evidence") or ""),
            "recommendation": str(cand.get("recommendation") or ""),
            "status": str(cand.get("status") or "open"),
            "discovered_via_run_id": run_id,
            # Verifier-CONFIRMED candidates carry verified=True from the
            # extractor; recon-level candidates honestly carry False.
            "verified": bool(cand.get("verified")),
            "verifier_verdict": str(cand.get("verifier_verdict") or "")[:500],
            # 8c2f1a postmortem defect: persist the candidate's explicit CWE tag.
            # Without it the stored finding re-infers its CWE from prose on the
            # next harvest ("...Injection..." -> cwe-89) while the candidate keys
            # on its literal cwe_hint (cwe-1236) — asymmetric _dedup_key means
            # every harvest pass appends a fresh duplicate of the same finding.
            "cwe_hint": str(cand.get("cwe_hint") or "")[:200] or None,
            "commands": list(cand.get("commands") or [])[:40],
            "owasp_id": oid or None,
            "id": _new_id(),
            "engagement_id": engagement_id,
            "created_at": now,
            "updated_at": now,
        }
        new_findings.append(finding)
        added += 1
        logger.info("merge_confirmed_findings[%s] appended finding '%s' to engagement %s",
                    run_id, finding["title"][:80], engagement_id)

    if added:
        eng["findings"] = _sort_findings(new_findings)
        eng["updated_at"] = now
        _write_engagement(engagement_id, eng)
    return added


def _harvest_late_verdicts(engagement_id: str, engagement: Optional[Dict[str, Any]] = None) -> int:
    """Idempotent re-scan of an engagement's runs for verifier-CONFIRMED findings
    (8c2f1a postmortem defect 2).

    Verdicts were harvested ONLY from the lead-driver exit hook — but a ghost/
    late verifier can append a CONFIRMED verdict HOURS after the driver exited
    (8c2f1a: a CONFIRMED 7.5-HIGH at 14:10, 4.5h after the 09:44 driver exit),
    and that finding then never reached the ledger or the report. This helper
    re-runs the same per-run merge (`_merge_confirmed_findings_into_engagement`)
    for every run linked to the engagement. It is IDEMPOTENT — the merge skips
    any dedup key already present, so re-scanning a fully-harvested engagement
    appends nothing — and cheap (reading verifier/*.jsonl only). Skips runs with
    no manifest. Called from the report.html GET (rare, never a hot path) and
    `_reconcile_reportwriter`; never raises. Returns the number of NEW findings."""
    if not engagement_id:
        return 0
    eng = engagement if engagement is not None else _read_engagement(engagement_id)
    if not eng:
        return 0
    added = 0
    for rid in (eng.get("run_ids") or []):
        if not rid or not _read_run_meta(rid):
            continue
        try:
            added += _merge_confirmed_findings_into_engagement(engagement_id, rid)
        except Exception as exc:
            logger.warning("harvest_late_verdicts[%s] run %s failed: %s",
                           engagement_id, rid, exc)
    if added:
        logger.info("harvest_late_verdicts[%s]: %d late confirmed finding(s) merged",
                    engagement_id, added)
    return added


@router.post("/engagements/{engagement_id}/findings")
async def create_finding(engagement_id: str, req: FindingCreate) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Serialize the read-modify-write against harvest/reconcile/report paths
    # that hold the same per-engagement lock (8c2f1a postmortem defect).
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id) or eng
        fid = _new_id()
        now = _now_iso()
        finding = {**req.dict(), "id": fid, "engagement_id": engagement_id,
                   "created_at": now, "updated_at": now}
        _add_finding(eng, finding)
        _write_engagement(engagement_id, eng)
    _invalidate_report_cache(engagement_id)
    return {"engagement": _public(eng), "finding": finding}


@router.patch("/engagements/{engagement_id}/findings/{finding_id}")
async def update_finding(engagement_id: str, finding_id: str, req: FindingUpdate) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    _valid_token(finding_id, "finding_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Serialize the read-modify-write against harvest/reconcile/report paths
    # (same per-engagement lock).
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id) or eng
        findings = eng.get("findings") or []
        for f in findings:
            if f.get("id") == finding_id:
                for k, v in req.dict(exclude_unset=True).items():
                    f[k] = v
                f["updated_at"] = _now_iso()
                eng["updated_at"] = _now_iso()
                _write_engagement(engagement_id, eng)
                _invalidate_report_cache(engagement_id)
                return {"engagement": _public(eng), "finding": f}
    raise HTTPException(status_code=404, detail="Finding not found")


@router.delete("/engagements/{engagement_id}/findings/{finding_id}")
async def delete_finding(engagement_id: str, finding_id: str) -> Dict[str, Any]:
    _valid_token(engagement_id, "engagement_id")
    _valid_token(finding_id, "finding_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Serialize the read-modify-write against harvest/reconcile/report paths
    # (same per-engagement lock).
    async with _engagement_lock(engagement_id):
        eng = _read_engagement(engagement_id) or eng
        eng["findings"] = [f for f in (eng.get("findings") or []) if f.get("id") != finding_id]
        eng["updated_at"] = _now_iso()
        _write_engagement(engagement_id, eng)
    _invalidate_report_cache(engagement_id)
    return {"engagement": _public(eng)}


# --- Findings-draft evidence gathering (DISK ONLY — never the live session API).
# Containers may be down (topology-routing blocker), so we read only persisted
# artifacts: phase_runtime results, guardrail verdicts.ndjson, approval reqs, and
# the captured coder56 message log. All bounded to keep the LLM prompt small. ---

def _read_verdicts_raw(run_id: str, limit: int = 80) -> List[Dict[str, Any]]:
    path = _guardrail_dir(run_id) / "verdicts.ndjson"
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _read_verdicts_full(run_id: str) -> List[Dict[str, Any]]:
    """ALL guardrail verdict records, untruncated. (_read_verdicts_raw tails +
    is used for compact UI display.) The findings-draft pipeline needs the
    complete command history so it doesn't drop findings whose PoCs ran early —
    the old `last 60 of N` window excluded the exact repro commands entirely."""
    return _read_verdicts_raw(run_id, limit=100_000)


# --- Verifier-status extraction (deterministic; NOT inferred by the LLM). ---
# coder56_verifier's verdicts are written by the agent as structured "emission"
# commands (printf/cat >> agent-memory or report files) carrying strong markers:
# `CLAIM [CONFIRMED by coder56_verifier]`, `VERDICT: CONFIRMED`, `OK TO REPORT:
# YES|NO`, `NOT_A_VULN`, `FALSE POSITIVE`. We tag each candidate finding from
# these so the report states verifier status authoritatively.

# A guardrail verdict record is a "finding emission" when its command carries a
# markdown header / memory-append scaffolding. Real pentest commands
# (curl/nmap/hydra) never contain '## ' or append to agent-memory/report files.
_RE_EMISSION = re.compile(
    r"##\s|>>\s*/outputs/\S*memory\S*|>>\s*/outputs/[^\s>]*report|FINDING\s*\[|CLAIM\s*\[",
    re.I,
)
# A CONFIRMED signal takes priority: the verifier routinely writes "False
# positives ruled out: NOT ..." inside a CONFIRMED verdict, so refutation
# markers must NOT override an explicit confirm. _RE_CONFIRMED covers every
# positive form; _RE_REFUTE only wins when there is no confirm.
_RE_CONFIRMED = re.compile(
    r"CONFIRMED\s+by\s+coder56_verifier|VERDICT\s*[:=]\s*CONFIRMED|"
    r"CLAIM\s*\[\s*CONFIRMED|OK\s+TO\s+REPORT\s*:\s*YES|"
    # coder56_verifier's machine-readable audit record ({"step":"VERDICT",...}):
    r'"verdict"\s*:\s*"CONFIRMED"|"ok_to_report"\s*:\s*"YES"', re.I
)
_RE_REFUTE = re.compile(
    r"NOT_A_VULN|NOT\s+CONFIRMED|FALSE\s+POSITIVE|REFUTED|RULED\s+OUT|"
    r"VERDICT\s*[:=]\s*(?:NOT|REFUTE)|OK\s+TO\s+REPORT\s*:\s*NO|"
    r'"verdict"\s*:\s*"(?:NOT_A_VULN|INCONCLUSIVE|REFUTED)"|"ok_to_report"\s*:\s*"NO"', re.I
)
_RE_OK_REPORT = re.compile(r"OK\s+TO\s+REPORT\s*:\s*(YES|NO)", re.I)
# C8: a finding that can ONLY be proved by mutating live state under a no-mod RoE,
# with no read-only oracle (coder56_verifier's NOT_CONFIRMABLE verdict). Distinct
# from REFUTED (NOT_CONFIRMABLE is "real but unprovable without breaking RoE", not
# "not a vuln"). Underscored, so it does NOT collide with "NOT CONFIRMED" (spaced).
_RE_NOT_CONFIRMABLE = re.compile(r"NOT_CONFIRMABLE|\"verdict\"\s*:\s*\"NOT_CONFIRMABLE\"", re.I)
# C6: HTTP method inference from finding title/asset/route (default GET) for the
# strict pre-verifier fingerprint.
_RE_METHOD = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
# C7/M9: the Lead's engagement-level early-stop token (it emits this when the
# objective is already satisfied). The lead driver respects it instead of grinding
# remaining phases (the Greedy A10 / Owasp2 A03 redundant-phase failure mode).
_RE_OBJECTIVE_MET = re.compile(r"OBJECTIVE\s+ALREADY\s+MET", re.I)
_RE_CVSS = re.compile(r"CVSS\s*(?:v[\d.]+)?\s*[:~]?\s*([0-9]+(?:\.[0-9]+)?)", re.I)
_RE_CWE = re.compile(r"(CWE-\d+|OWASP\s+A\d{2}:?\d{4})", re.I)
# Candidate dedup/noise helpers. Emissions often repeat the same finding in two
# places (a `printf` VERIFIER verdict AND a `MEMORY.md` FINDING block) and include
# command-wrapper noise (`mkdir … && cat >>`, `cd /tmp && …`). These collapse
# the candidate set so the reporter agent does one unit of work per real finding.
# An HTTP endpoint path. The negative lookahead excludes filesystem/infra paths
# (/outputs, /tmp, /proc, …) that leak into command bodies — without it a stub
# like "TOKEN / SCOPE" (whose body is full of /outputs/... plumbing) gets
# affected_asset="/outputs/" and is mistaken for a real finding.
_RE_ENDPOINT = re.compile(
    r"/(?!outputs|tmp|proc|sys|opt|srv|root|var|home|etc|dev|run)(?:api/)?[a-z][a-z0-9_/-]{2,}",
    re.I)
_RE_VULNCLASS = re.compile(
    r"\b(bfla|broken[- ]access|sql(?:i|injection)|injection|xss|csrf|ssrf|idor|rce|"
    r"lfi|rfi|csv|formula|unauth(?:orized)?|default\s+cred|priv(?:ilege)?\s*esc|"
    r"open\s+redirect|token|mint|orphan|inflat)\b", re.I)
_RE_SHELL_VERB = re.compile(r"^\s*(cd|mkdir|ls|echo|cat|cp|mv|rm|chmod|chown|export|"
                            r"sed|awk|grep|wc|find|touch|ln|tar|git|docker|kubectl)\b", re.I)


def _verifier_status(text: str):
    """Return (verified, verdict_line) parsed from an emission's text.

    verified is True only on an explicit CONFIRMED (by the verifier / VERDICT:
    CONFIRMED / OK TO REPORT: YES). Refutation (NOT_A_VULN / FALSE POSITIVE /
    OK TO REPORT: NO) is applied ONLY when no confirm signal is present — the
    verifier writes "false positives ruled out" inside confirmed verdicts."""
    ok = _RE_OK_REPORT.search(text)
    oktxt = f" — OK TO REPORT: {ok.group(1).upper()}" if ok else ""
    explicit_no = bool(ok and ok.group(1).upper() == "NO")
    if _RE_CONFIRMED.search(text) and not explicit_no:
        return True, "CONFIRMED by coder56_verifier" + oktxt
    # C8/A3: NOT_CONFIRMABLE is "real but only provable by mutating live state under
    # a no-mod RoE" — NOT a refutation. Recognize it distinctly so it is never labeled
    # INCONCLUSIVE/empty (which would silently drop the RoE conflict the agent raised).
    if _RE_NOT_CONFIRMABLE.search(text):
        return False, "NOT_CONFIRMABLE by coder56_verifier" + oktxt
    if _RE_REFUTE.search(text):
        m = re.search(r"(NOT_A_VULN|FALSE POSITIVE|NOT CONFIRMED|REFUTED|RULED OUT)[^.]*",
                      text, re.I)
        return False, (m.group(0).strip() if m else "REFUTED") + oktxt
    return False, ""


def _decode_emission_body(command: str) -> str:
    """Recover the human-readable text the agent wrote via printf/heredoc.

    Emission commands look like:
      printf '\\n## %s — asset\\n- CLAIM ...\\n' "$(date -u +%FT%TZ)" >> FILE
      cat >> FILE <<'EOF'\\n## ...\\n- FINDING [NEW-1] ...\\nEOF
    Strip the shell scaffolding and un-escape \\n/\\x27 so the body reads as
    plain markdown (best-effort; the LLM also tolerates the raw form)."""
    body = command
    body = re.sub(r"^\s*printf\s+", "", body)
    body = re.sub(r"^\s*cat\s+>>?\s*\S+\s*<<-?'?EOF'?", "", body)
    body = re.sub(r"<<-?'?EOF'?", "", body)
    body = re.sub(r'"\$\(date[^"]*\)"', "", body)
    body = re.sub(r"\s*>>?\s*/\S+(\s*[;&]\s*(?:echo|&&)\s*['\"].*?)?\s*$", "", body, flags=re.S)
    body = (body.replace("\\n", "\n").replace("\\t", "\t")
                .replace("\\x27", "'").replace('\\"', '"').replace("\\\\", "\\"))
    return body.strip().strip("'\"").strip()


_RE_HOSTPORT = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}:\d+)\b")
# An action command (network/exploit) — used to pull LITERAL repro commands out
# of the verdict log deterministically (what the reporter used to grep for, slowly).
_RE_ACTION_CMD = re.compile(
    r"\b(curl|wget|nmap|nc|netcat|sqlmap|nikto|ffuf|gobuster|hydra|john|hashcat|"
    r"smbclient|rpcclient|enum4linux|ldapsearch|dig|kubectl|openssl|python3?|node|"
    r"telnet|ftp|ssh)\b|https?://|/api/|/dev/tcp", re.I)
# A STRICT tool invocation (the binary itself) — used to tell a real repro command
# from prose that merely mentions a path ("POST /api/auth/register" contains /api/
# but is not a command). Used to decide whether an inline `repro` entry is usable
# as-is or whether we must scan the verdict log for the actual command.
_RE_CMD_TOOL = re.compile(
    r"\b(curl|wget|nmap|nc|netcat|sqlmap|nikto|ffuf|gobuster|hydra|john|hashcat|"
    r"smbclient|rpcclient|enum4linux|ldapsearch|dig|kubectl|openssl|python3?|node|"
    r"telnet|ftp|ssh)\b", re.I)
# A session/env/state note, not a finding ("ENV RESET since prior engagements…",
# "DB wiped", "STATE END-SESSION …"). These get emitted as memory write-ups and
# must be dropped from the findings set. Searched (unanchored) over the title and
# the body prefix — the body often opens with a "## date" header before the note.
_RE_NONFINDING_START = re.compile(
    r"\b(env\s+reset|db\s+(wiped|reset)|prior\s+engagements|"
    r"session\s+(start|end|state|reset)|state\s+(end|start)[- ]session|"
    r"new\s+this\s+session)\b", re.I)
# Lines in an emission body that are NEVER finding text — shell variable
# assignments (MEM=/SLUG=/F=/AUDIT=…), output redirects to /outputs, and
# memory/verifier/phase path scaffolding. The title picker skips these so a
# finding's title is the claim sentence, not the shell plumbing around it.
_RE_EMISSION_TITLE_NOISE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*\s*="            # VAR= assignment (MEM=, SLUG=, F=, AUDIT=…)
    r"|>>\s*['\"]?(?:/outputs|\$)"             # >> redirect (to /outputs or a $var)
    r"|memory/MEMORY\.md"
    r"|/outputs/\$RUN_ID/(?:verifier|memory|phase)"
    r"|^\s*(?:cat\s+>>|mkdir|printf|echo|which)\b", re.I)
# Header scaffolding that prefixes a real claim line — stripped from the title
# (the finding text following it is kept, including its route).
_RE_EMISSION_TITLE_PREFIX = re.compile(
    r"^(VERIFIER\s*\([^)]*\)\s*:?\s*|CLAIM\s*\[[^\]]*\]\s*:?\s*"
    r"|FINDING\s*\[[^\]]*\]\s*|-\s*)", re.I)
# A title that is NOT a finding — process/coverage stubs the agent writes as
# memory headers, and shell fragments scraped out of command plumbing. The
# emission log captures the agent's own write-ups verbatim, so a "VERIFIER GATE
# RUN (… all CONFIRMED)" or `python3 - "$F" <<'PY'` line can otherwise be ingested
# as a (sometimes verified=True!) finding. Reject these outright.
_RE_GARBAGE_TITLE = re.compile(
    r"^(VERIFIER\s+GATE\s+RUN"            # "VERIFIER GATE RUN (coder56_verifier invoked x3…)"
    r"|VERIFIER\s+CONFIRMED\s*\("         # "VERIFIER CONFIRMED (independent repro this run)…"
    r"|CONFIRMED\s+A\d{2}\s+vulns"        # "CONFIRMED A04 vulns (both coder56_verifier…)"
    r"|Evidence-capture\s+artifacts"       # "Evidence-capture artifacts (this run)"
    r"|PHASE\s+\d+\s+OBJECTIVE"            # "PHASE 9 OBJECTIVE: …"
    r"|Claim\s*:)"                         # raw "Claim: …" header (a restated dup, not a title)
    r"|<<\s*['\"]?[A-Z]{2,}"               # heredoc tail: <<'PY'
    r"|python3?\s+-\s"                     # "python3 - "$F""
    r"|\$\{?[A-Za-z_][A-Za-z0-9_]*\s*=",   # shell assignment as title: $VAR= / MEM=
    re.I)
# A title with NO lowercase letter is a fragment (e.g. "TOKEN / SCOPE"), not a
# finding sentence. Real findings always contain lowercase prose.
_RE_NO_LOWER = re.compile(r"^[^a-z]*$")


def _severity_for(cvss: Optional[float], verdict: str, body: str, verified: bool) -> str:
    low = body.lower()
    # Refuted/by-design → info. BUT only when NOT verifier-confirmed: a CONFIRMED
    # finding's body routinely contains "false positives ruled out: NOT ..." (the
    # verifier explaining why it's real), which must not be misread as a refutation.
    is_refuted = (not verified) and (
        (verdict and any(k in verdict.lower() for k in
                         ("not_a_vuln", "false positive", "refuted", "ruled out",
                          "not_confirmable", "could_not_test", "unverifiable")))
        or any(k in low for k in ("not_a_vuln", "false positive", "refuted", "ruled out",
                                  "no impact", "standard k8s", "by design", "intended behavior"))
    )
    if is_refuted:
        return "info"
    if cvss is None:
        if any(k in low for k in ("critical", "rce", "remote code", "token mint",
                                  "supply inflation", "mint blockchain")):
            return "critical"
        if any(k in low for k in ("bfla", "broken access", "privilege", " admin",
                                  "delete", "unauth", "idor")):
            return "high"
        if any(k in low for k in ("injection", "sqli", "xss", "csv", "formula")):
            return "medium"
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss >= 0.1:
        return "low"
    return "info"


# A phase memory note the agent appends to MEMORY.md after each phase, e.g.
# "## 2026-07-22T15:51Z — 10.77.1.12 (Phase 2 injection)" or the printf form
# "## %s — 10.77.1.12 (Phase 2 sqlmap verdict)". These are running prose — recon
# facts or NEGATIVE results ("all SQLi vectors CLEAN", "Confirmed parameterized")
# — NOT findings. They routinely contain a vuln-class word ("injection", "SQLi")
# which must NOT promote them into the findings set.
_RE_MEMORY_NOTE = re.compile(
    r"##\s*(?:\d{4}-\d{2}-\d{2}T|%s\b)"   # dated header OR unsubstituted printf %s header
    r"|M=\"/outputs[^\"]*memory"            # memory-path variable assignment (M="...")
    r"|\$RUN_ID/memory"                     # memory path reference
    r"|\(Phase\s+\d",                       # "(Phase N …)" tag on a memory header
    re.I | re.M)
# 8c2f1a postmortem (ALSO): a `cat >> .../memory/MEMORY.md` BOOKKEEPING command
# whose body is a pipe-record dump (AUTH_ENDPOINT|…, IDOR_BOLA|…) became a
# critical-severity finding titled "Append phase 4 findings to memory" — the
# pipe records carry vuln-class words (IDOR_BOLA), so the vuln-class branch of
# _has_finding_substance admitted them. An emission whose COMMAND targets the
# agent's memory store is only a finding when its body carries an AUTHORITATIVE
# finding marker (FINDING[ / CLAIM[ / VERDICT: / OK TO REPORT / CONFIRMED-by-
# verifier) — the vuln-class fallback alone must never promote memory notes.
_RE_MEMORY_BOOKKEEPING = re.compile(r"/memory/", re.I)
# The authoritative-finding-marker branch of _has_finding_substance, standalone.
_RE_FINDING_MARKER = re.compile(
    r"CLAIM\s*\[|FINDING\s*\[|CONFIRMED\s+by\s+coder56_verifier|"
    r"NOT_A_VULN|OK\s+TO\s+REPORT|VERDICT\s*[:=]", re.I)


def _has_finding_substance(c: Dict[str, Any]) -> bool:
    """True if a candidate looks like an actual finding (not a memory note, env
    reset, or pasted script). Requires an AUTHORITATIVE finding marker (CLAIM[/,
    FINDING[, CONFIRMED-by-verifier, NOT_A_VULN, OK TO REPORT, VERDICT:) or a
    vuln-class. A bare note like "ENV RESET… DB wiped" that merely contains the
    words "false positive" in passing is NOT a finding and is dropped."""
    body = c["body"]
    if _RE_FINDING_MARKER.search(body):
        return True
    # A phase memory note is recon/negative-result prose, not a finding — never
    # let a bare vuln-class word promote it (the original garbage-draft bug).
    if _RE_MEMORY_NOTE.search(body):
        return False
    return bool(_RE_VULNCLASS.search(body))


def _split_findings(body: str) -> List[str]:
    """Split one emission body into per-finding chunks. Most emissions are a
    single finding (returned as-is), but the agent sometimes consolidates several
    in one MEMORY.md write-up ("- FINDING [NEW-1] …\\n- FINDING [NEW-2] …"); those
    are split so each finding becomes its own candidate (otherwise the blob's
    endpoints span both and the dedup absorbs the separate write-ups)."""
    if len(re.findall(r"^[-*]\s*FINDING\s*\[", body, flags=re.M)) >= 2:
        parts = re.split(r"(?=\s*[-*]\s*FINDING\s*\[)", body)
        return [p.strip() for p in parts if re.search(r"FINDING\s*\[", p)]
    return [body]


def _literal_commands(body: str, title: str, repro: List[str],
                      verdicts: List[Dict[str, Any]]) -> List[str]:
    """Exact repro commands for a finding. Prefer inline repro that already looks
    like commands; otherwise score every action-command in the verdict log by how
    specifically it matches THIS finding and return the top ones. Scoring on the
    HTTP method (from the finding's title) + the finding's endpoint path/segments
    is what makes the actual PoC (e.g. `curl -X DELETE .../api/items/69`) outrank
    generic recon probes of the same path (`curl .../api/items`), which a naive
    substring match would return first."""
    # Inline repro is only usable as-is if it actually invokes a tool; prose like
    # "POST /api/auth/register" contains /api/ but is not a command (scan instead).
    cmds = [r for r in repro if _RE_CMD_TOOL.search(r)]
    if cmds:
        return cmds[:8]
    tm = re.search(r"\b(DELETE|POST|PUT|PATCH)\b", title or "")
    method = tm.group(1).upper() if tm else ""
    paths = [m.group(0) for m in _RE_ENDPOINT.finditer(body)]
    primary = paths[0] if paths else ""
    segs = {s for s in re.split(r"[:/]+", primary)
            if len(s) > 3 and s.lower() not in ("api", "http", "https", "v1", "v2")}
    scored: List[tuple] = []
    for v in verdicts:
        c = str(v.get("command") or "").strip()
        if not c or _RE_EMISSION.search(c) or not _RE_ACTION_CMD.search(c):
            continue  # skip the agent's own write-up commands + non-actions
        score = 0
        if method and re.search(rf"\B(-X|--request)\s*\"?{method}\"?\b", c, re.I):
            score += 5
        elif method and method in c.upper():
            score += 2
        for p in paths[:3]:
            if p and p in c:
                score += 2
        for seg in segs:
            if seg in c:
                score += 1
        if score > 0:
            scored.append((score, c))
    scored.sort(key=lambda x: -x[0])
    out: List[str] = []
    for _s, c in scored:
        if c not in out:
            out.append(c)
        if len(out) >= 6:
            break
    return out


def _impact_reco(body: str) -> tuple:
    low = body.lower()
    if "bfla" in low or "broken" in low or "authoriz" in low or " role" in low:
        return ("Broken access control: a low-privilege user can perform an action "
                "reserved for administrators (privilege escalation / unauthorized state change).",
                "Enforce server-side authorization (role check) on the endpoint; never rely on the client.")
    if "inject" in low or "sqli" in low or "sql" in low:
        return ("Injection allows unauthorized data access or manipulation.",
                "Use parameterized queries / prepared statements; never concatenate user input.")
    if "csv" in low or "formula" in low:
        return ("CSV/formula injection executes when the export is opened in a spreadsheet app.",
                "Prefix or strip formula characters (= + - @) in CSV-exported fields.")
    if "unauth" in low or "default" in low:
        return ("Weak/default authentication allows unauthorized access.",
                "Remove default credentials; enforce strong auth and credential rotation.")
    return ("See description.", "See description.")


def _extract_emission_findings(run_id: str) -> List[Dict[str, Any]]:
    """Deterministically recover COMPLETE, output-shaped findings from the run's
    guardrail command log. Each verdict record whose command carries a markdown
    header / verdict token is an "emission" — the agent's structured write-up of
    a finding/verdict. This builds full FindingCreate-shaped dicts (title,
    severity, cvss, asset, verified, verifier_verdict, exact commands, evidence,
    description/impact/recommendation) so the reporter agent's job is just to
    emit them — no composition reasoning (which stalled glm-5.2). Verifier status
    is PARSED (not inferred); exact commands are pulled from the verdict log."""
    verdicts = _read_verdicts_full(run_id)
    raw: List[Dict[str, Any]] = []
    for v in verdicts:
        cmd = str(v.get("command") or "")
        if not _RE_EMISSION.search(cmd):
            continue
        # Memory-bookkeeping commands (cat >> .../memory/MEMORY.md) are the agent
        # persisting ITS OWN running notes, not reporting a finding. Drop the ones
        # whose body carries NO authoritative finding marker — their pipe-record
        # dump (IDOR_BOLA|…) would otherwise be promoted into a bogus finding by
        # the vuln-class fallback in _has_finding_substance (8c2f1a: a critical
        # "Append phase 4 findings to memory"). A structured FINDING[/CLAIM[
        # write-up that happens to live in MEMORY.md IS a finding and is kept.
        if _RE_MEMORY_BOOKKEEPING.search(cmd) and not _RE_FINDING_MARKER.search(cmd):
            continue
        # One emission can consolidate SEVERAL findings (a MEMORY.md write-up with
        # multiple "- FINDING [NEW-N]" blocks). Split those so each becomes its own
        # candidate instead of one blob whose endpoints span (and absorb) the others.
        for body in _split_findings(_decode_emission_body(cmd)):
            if len(body.strip()) < 20:
                continue
            # An emission is a CLAIM, not a confirmation. The verifier's
            # machine-readable VERDICT record (read by _extract_verifier_findings)
            # is the only thing that makes a finding confirmed — NOT the agent's
            # own prose, which routinely says "CONFIRMED" inside process stubs
            # ("VERIFIER GATE RUN … all CONFIRMED", "python3 … <<'PY'") that then
            # get counted as confirmed findings. So: trust only REFUTATIONS from
            # prose (a NOT_A_VULN / NOT_CONFIRMABLE claim correctly lowers the
            # finding to info); a prose "CONFIRMED" does not confirm here.
            vflag, vline = _verifier_status(body)
            verified = False
            verdict = (vline if (vline and not vflag) else "")
            repro: List[str] = []
            m = re.search(r"[-*]?\s*(?:verifier\s+)?repro(?:duction)?\s*:?\s*(.*?)(?:\n\s*[-*]\s|\Z)",
                          body, re.I | re.S)
            if m:
                repro = [ln.strip(" -*") for ln in re.split(r"\s*->\s*|\n", m.group(1)) if ln.strip(" -*")][:12]
            cvss = None
            cm = _RE_CVSS.search(body)
            if cm:
                try:
                    cvss = float(cm.group(1))
                except ValueError:
                    cvss = None
            cwes = sorted({mm.group(1) for mm in _RE_CWE.finditer(body)})
            # Title = first line that is finding text. Skip dated headers, lines
            # opening with an em-dash clause, and the shell/path scaffolding the
            # emission log wraps claims in (_RE_EMISSION_TITLE_NOISE). VERIFIER /
            # CLAIM / FINDING header lines are kept (the claim follows them) and
            # have only the prefix stripped below.
            title = ""
            for ln in body.split("\n"):
                ln = ln.strip().lstrip("#").strip(" -*")
                if (not ln or re.match(r"^\d{4}-\d{2}-\d{2}T", ln)
                        or " — " in ln[:40] or _RE_EMISSION_TITLE_NOISE.search(ln)):
                    continue
                title = ln
                break
            title = _RE_EMISSION_TITLE_PREFIX.sub("", title or "").strip()[:200]
            raw.append({"run_id": run_id, "verified": verified, "verifier_verdict": verdict,
                        "cvss_hint": cvss, "cwe_hint": ", ".join(cwes), "repro": repro,
                        "title_raw": title, "body": body[:4000]})
    # De-noise: drop shell-wrapper emissions AND non-finding notes/scripts
    # (memory notes like "ENV RESET…", pasted "#!/bin/bash" scripts, recon dumps).
    filtered = [c for c in raw
                if c["title_raw"]
                and not _RE_GARBAGE_TITLE.search(c["title_raw"])
                and not _RE_NO_LOWER.match(c["title_raw"])
                and not _RE_SHELL_VERB.match(c["body"].lstrip("\n").strip())
                and not c["body"].lstrip().startswith("#!")
                and not _RE_NONFINDING_START.search(c["body"][:300])
                and not _RE_NONFINDING_START.search(c["title_raw"])
                and _has_finding_substance(c)]
    if not filtered:
        # Strict: when the de-noise filter drops everything (no structured
        # CLAIM/FINDING/VERDICT emissions were written), return EMPTY rather than
        # re-admitting memory notes or pasted scripts that merely contain a
        # vuln-class word (the original garbage-draft bug). The phase-report
        # parser (_extract_findings_from_phase_reports) is the authoritative
        # fallback when this returns nothing.
        return []
    # Dedup: collapse a finding restated in two places (a printf VERIFIER verdict
    # AND a MEMORY.md FINDING block). Identity = vuln-class + the finding's PRIMARY
    # endpoint (the one in its CLAIM/FINDING title line) — NOT every endpoint
    # mentioned in the body, because two DIFFERENT findings routinely cite the
    # same sibling endpoints in their admin-gate cross-check ("…gate IS on
    # /api/categories, /api/users…") and must not merge on those.
    deduped: Dict[str, Dict[str, Any]] = {}
    for c in filtered:
        mvc = _RE_VULNCLASS.search(c["body"])
        vc = (mvc.group(1).lower().replace(" ", "") if mvc else "")
        epm = _RE_ENDPOINT.search(c["title_raw"])
        ep = (epm.group(0).lower().rstrip("/") if epm else "")
        key = f"{vc}|{ep}" or c["title_raw"][:48].lower()
        prev = deduped.get(key)
        if prev is None or len(c["body"]) > len(prev["body"]):
            deduped[key] = c

    findings: List[Dict[str, Any]] = []
    for c in deduped.values():
        body = c["body"]
        title = c["title_raw"][:200]
        hp = _RE_HOSTPORT.search(body)
        ep = _RE_ENDPOINT.search(body)
        asset = (hp.group(1) if hp else "")
        if ep:
            asset = (asset + " " + ep.group(0)).strip()
        sev = _severity_for(c["cvss_hint"], c["verifier_verdict"], body, c["verified"])
        commands = _literal_commands(body, c["title_raw"], c["repro"], verdicts)
        desc = re.sub(r"\s+", " ", body).strip()[:700]
        ev = ""
        em = re.search(r"[-*]?\s*(?:verifier\s+)?repro(?:duction)?\s*:?\s*(.*?)(?:\n\s*[-*]\s|\Z)",
                       body, re.I | re.S)
        if em:
            ev = re.sub(r"\s+", " ", em.group(1)).strip()[:700]
        if not ev:
            ev = desc[:400]
        impact, reco = _impact_reco(body)
        findings.append({
            "run_id": c["run_id"],
            "title": title,
            "severity": sev,
            "cvss": c["cvss_hint"],
            "affected_asset": asset[:200],
            "verified": c["verified"],
            "verifier_verdict": c["verifier_verdict"],
            "commands": commands,
            "evidence": ev,
            "description": desc,
            "impact": impact,
            "recommendation": reco,
            "status": "open",
            "cwe_hint": c["cwe_hint"],
        })
    return findings


# --- Phase-report findings parser (authoritative source of the REAL findings). ---
# The phase workers (coder56_phase) write their findings as structured prose in
# run.json -> phase_runtime[].result (the report returned to the lead) — typically
# a consolidation with "### F# — Title (CWE-…)" blocks each carrying Vector / Flaw
# / Proof / CVSS rows. This is the authoritative record of what was actually
# found: far more reliable than scraping the guardrail bash-emission log (which
# only sees memory-append commands and misreads recon/negative-result notes as
# findings). Used as the PRIMARY findings source for the reporter; coder56_verifier
# CONFIRMED status is merged in from /outputs/<run_id>/verifier/*.jsonl (per-run,
# authoritative) with /outputs/verifier/*.jsonl as a backward-compat fallback, when
# actually ran. Guarantees the agent's real F#/D# findings reach the report even
# when the verifier could not be spawned.
_RE_PHASE_FINDING_HEAD = re.compile(
    r"(?:^|\n)\s*##+\s*((?:F|D)\d+)\s*(?:\([^)]*\)\s*)?[—\-–:.]+\s*(.+)", re.M)
_RE_PHASE_CVSS = re.compile(r"CVSS[^\n]*?=\s*\*{0,2}\s*([0-9]+(?:\.[0-9]+)?)", re.I)


def _phase_table_row(block: str, label: str) -> str:
    """Value of a markdown-table row '**Label** | value' (or '**Label**: value'),
    trimmed. Best-effort: stops at the next cell."""
    m = re.search(rf"\*\*{re.escape(label)}[^\n]*?\*\*\s*[:|]?\s*(.+)", block, re.I)
    if not m:
        return ""
    val = re.split(r"\s{2,}\|\s*\*\*|\n\s*\|", m.group(1))[0]
    return val.strip(" |`").strip()


# =============================================================================
# Verifier JSONL salvage (VERIFIER_DROPPED_FINDINGS_REPORT 2026-08-25, Rec 1).
# The verifier hand-writes audit/VERDICT records despite the json.dumps rule in
# its prompt (i.1/j); three real loss classes were observed in the 2026-08-25
# 37-agent audit, and each one makes strict json.loads drop the WHOLE record —
# including CONFIRMED, ok_to_report=YES verdicts:
#   (1) unescaped inner double quotes in a string value —
#       "evidence_file":"/outputs/"<run_id>"/verifier/"<slug>".jsonl"  (a
#       CONFIRMED 4.3 MEDIUM CWE-209 finding was lost exactly this way);
#   (2) trailing shell garbage after the closing brace — a stray `echo` +
#       misplaced quote appended by the writing command;
#   (3) invalid escapes (\xNN — JSON allows only \uXXXX) and truncated
#       mid-record lines (the jwt-logout VERDICT cut mid-string).
# Every consumer of /outputs/<run_id>/verifier/*.jsonl now parses through
# _read_verifier_records, which repairs what it can, and
# _verifier_parse_alerts alarms on any candidate file whose VERDICT record
# stayed unrecoverable instead of silently ignoring it.
# =============================================================================

_RE_BAD_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
# chars that may legally follow a closing quote in a JSON document
_TOL_VALUE_CLOSE = set(',}]:')

_TOL_LEGAL_ESCAPE = set('"\\/bfnrtu')


def _fix_json_escapes(s: str) -> str:
    r"""Repair escape sequences strict JSON rejects: \xNN -> the literal char,
    and a backslash before any char that cannot start a JSON escape -> that
    char alone (a lone backslash-backtick was the command-injection file's
    failure). \uXXXX and the legal \" \\ \/ \b \f \n \r \t pass untouched."""
    s = _RE_BAD_HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), s)
    return re.sub(r'\\(?!["\\/bfnrtu])', "", s)


def _tol_scan_string(s: str, i: int) -> Tuple[Optional[str], int]:
    """Tolerant JSON string scan starting at the OPENING quote s[i]=='"'.
    Repair rule for unescaped inner quotes: a '"' only CLOSES the string when
    the next non-space char can legally follow a closed value (, } ] : or end
    of line); otherwise it is a literal quote inside the value. Returns
    (value, index_after_close) or (None, len(s)) when truncated unterminated."""
    n = len(s)
    i += 1
    out: List[str] = []
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt == "u" and i + 6 <= n:
                try:
                    out.append(chr(int(s[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            out.append(nxt)
            i += 2
            continue
        if c == '"':
            j = i + 1
            while j < n and s[j] in " \t\r\n":
                j += 1
            if j >= n or s[j] in _TOL_VALUE_CLOSE:
                return "".join(out), j
            out.append('"')  # embedded unescaped quote — keep it literally
            i += 1
            continue
        out.append(c)
        i += 1
    return None, n


def _tolerant_json_object(s: str) -> Optional[Dict[str, Any]]:
    """Best-effort recovery of ONE flat-ish JSON object from a corrupt line.
    Used only after strict parse + escape repair + raw_decode all failed.
    A truncated tail yields the fields parsed so far rather than nothing (a
    VERDICT cut mid-`reason` still carries its verdict/ok_to_report/cvss)."""
    n = len(s)

    def _ws(i: int) -> int:
        while i < n and s[i] in " \t\r\n":
            i += 1
        return i

    i = _ws(0)
    if i >= n or s[i] != "{":
        return None
    i += 1
    obj: Dict[str, Any] = {}
    while True:
        i = _ws(i)
        if i >= n:
            return obj or None            # truncated: salvage what parsed
        if s[i] == "}":
            return obj
        if s[i] == ",":
            i += 1
            continue
        if s[i] != '"':
            return obj or None            # structure unrecoverable here
        key, j = _tol_scan_string(s, i)
        if key is None:
            return obj or None
        i = _ws(j)
        if i >= n or s[i] != ":":
            return obj or None
        i = _ws(i + 1)
        if i >= n:
            return obj or None
        c = s[i]
        if c == '"':
            val, i = _tol_scan_string(s, i)
            if val is None:
                return obj or None        # truncated inside this value
        elif c.isdigit() or c == "-":
            m = re.match(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", s[i:])
            if not m:
                return obj or None
            txt = m.group(0)
            val = float(txt) if any(ch in txt for ch in ".eE") else int(txt)
            i += len(txt)
        elif s.startswith("true", i):
            val, i = True, i + 4
        elif s.startswith("false", i):
            val, i = False, i + 5
        elif s.startswith("null", i):
            val, i = None, i + 4
        elif c in "[{":
            # nested value: balanced scan (string-aware via the tolerant
            # close rule), then strict-parse the slice; raw text as fallback.
            depth = 0
            j = i
            close_of = "}" if c == "{" else "]"
            while j < n:
                ch = s[j]
                if ch == '"':
                    _, j2 = _tol_scan_string(s, j)
                    if j2 >= n:
                        return obj or None
                    j = j2
                    continue
                if ch in "{[":
                    depth += 1
                elif ch in "}]":
                    depth -= 1
                    if depth == 0 and ch == close_of:
                        j += 1
                        break
                j += 1
            raw = s[i:j]
            try:
                val = json.loads(raw)
            except Exception:
                val = raw
            i = j
        else:
            return obj or None
        obj[key] = val


def _salvage_json_objects(ln: str) -> Tuple[List[Dict[str, Any]], bool]:
    """ALL dict records recoverable from one physical JSONL line, plus whether
    any repair was needed. Order of attack: strict parse; escape-repaired
    parse; a raw_decode LOOP over the line — which recovers multiple objects
    concatenated onto one line by a missing newline (the jwt-logout CONFIRMED
    9.1 CRITICAL verdict was lost exactly this way: `...logout"}
    {"step":"VERDICT",...`) and tolerates trailing garbage (a stray `echo`);
    finally the tolerant scanner for a corrupt final object, which salvages
    the fields parsed before a mid-record truncation."""
    s = ln.strip()
    if not s.startswith("{"):
        return [], False
    try:
        d = json.loads(s)
        return ([d], False) if isinstance(d, dict) else ([], False)
    except Exception:
        pass
    fixed = _fix_json_escapes(s)
    out: List[Dict[str, Any]] = []
    # reaching this loop at all means strict parse failed — any recovery here
    # (escape repair, concatenated objects, trailing garbage, tolerant scan)
    # counts as salvage
    salvaged = True
    dec = json.JSONDecoder()
    pos, n = 0, len(fixed)
    while pos < n:
        # skip whitespace / separators between concatenated objects
        while pos < n and (fixed[pos].isspace() or fixed[pos] in ",;"):
            pos += 1
        if pos >= n:
            break
        if fixed[pos] != "{":
            nxt = fixed.find("{", pos)
            if nxt == -1:
                break
            salvaged = True   # leading garbage (stray echo/quoting) skipped
            pos = nxt
        try:
            obj, end = dec.raw_decode(fixed, pos)
        except ValueError:
            obj = _tolerant_json_object(fixed[pos:])
            if isinstance(obj, dict) and obj:
                out.append(obj)
                salvaged = True
            break  # corrupt from here — best effort stops after this object
        if isinstance(obj, dict):
            out.append(obj)
        if end <= pos:
            break
        pos = end
    if out:
        return out, salvaged
    return [], False


def _salvage_json_line(ln: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Single-record view of _salvage_json_objects (first record on the line)
    for consumers that only care whether THIS line carries a record."""
    ds, salvaged = _salvage_json_objects(ln)
    return (ds[0] if ds else None), salvaged


def _read_verifier_records(path: Path) -> Tuple[List[Dict[str, Any]], List[int]]:
    """Every dict record in a verifier .jsonl, line-by-line, salvaging
    malformed lines (and concatenated records) instead of skipping them.
    Returns (records, bad_line_numbers) so callers can distinguish 'file has
    verdicts' from 'file has content we still cannot read'."""
    recs: List[Dict[str, Any]] = []
    bad: List[int] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return recs, bad
    for idx, ln in enumerate(text.splitlines()):
        if not ln.strip():
            continue
        ds, _ = _salvage_json_objects(ln)
        if ds:
            recs.extend(ds)
        else:
            bad.append(idx)
    return recs, bad


def _verifier_parse_alerts(run_id: str) -> List[str]:
    """Operator-visible alarms for verifier candidate files that carry content
    but NO parseable (even salvaged) VERDICT record — the silent-loss class
    where a verdict exists on disk yet never reaches any report. Empty when
    every candidate file either has a VERDICT record or never got content."""
    vdir = OUTPUTS_DIR / run_id / "verifier"
    alerts: List[str] = []
    if not vdir.exists():
        return alerts
    for jf in sorted(vdir.glob("*.jsonl"), key=lambda p: p.name):
        recs, bad = _read_verifier_records(jf)
        if not recs and not bad:
            continue  # empty file — nothing was ever attempted
        if any(str(r.get("step", "")).upper() == "VERDICT" for r in recs):
            continue  # verdict recovered
        alerts.append(
            f"{jf.name}: NO parseable VERDICT record ({len(recs)} audit record(s), "
            f"{len(bad)} unparseable line(s)) — a verdict may have been written but "
            f"lost to malformed/truncated serialization; re-run verification or "
            f"re-emit the record."
        )
    return alerts


def _verifier_verdict_for(run_id: str, endpoint: str, title: str) -> tuple:
    """Best-effort: does a coder56_verifier VERDICT record confirm or refute THIS
    finding? Matches by the finding's endpoint path appearing in the verdict's
    route/claim. Reads the per-run dir /outputs/<run_id>/verifier/*.jsonl first
    (authoritative, isolated from other engagements), then the global
    /outputs/verifier/*.jsonl as a backward-compat fallback — there gated to files
    modified at/after the run's launch so prior engagements' verdicts don't
    contaminate. Returns (verified, verdict_line)."""
    # Per-run verifier dir is authoritative (isolated from other engagements).
    # The global /outputs/verifier/ is a backward-compat fallback for runs that
    # wrote there before per-run isolation, still gated by the launch-time check.
    run_vdir = OUTPUTS_DIR / run_id / "verifier"
    vdir = OUTPUTS_DIR / "verifier"
    if not (run_vdir.exists() or vdir.exists()):
        return False, ""
    launched = (_read_run_meta(run_id).get("launched_at") or "")[:19]
    needles = [endpoint] if endpoint else []
    needles += [n for n in re.findall(r"/(?:api/)?[a-z][a-z0-9_/-]{2,}", title or "", re.I)
                if n not in needles and len(n) > 4]
    needles = [n for n in needles if n]
    if not needles:
        return False, ""
    try:
        cand: List[Path] = []
        if run_vdir.exists():
            cand += list(run_vdir.glob("*.jsonl"))
        if vdir.exists():
            cand += list(vdir.glob("*.jsonl"))
        if not cand:
            return False, ""
        files = sorted(cand, key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        return False, ""
    import datetime as _dt
    for jf in files:
        if launched:
            try:
                if _dt.datetime.fromtimestamp(jf.stat().st_mtime).isoformat() < launched:
                    continue
            except Exception:
                pass
        try:
            raw = jf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in raw.splitlines():
            for d in _salvage_json_objects(line)[0]:
                if d.get("step") != "VERDICT":
                    continue
            route = f"{d.get('route', '')} {d.get('claim', '')}"
            if not any(n in route for n in needles):
                continue
            verdict = str(d.get("verdict", "")).upper()
            ok = str(d.get("ok_to_report", "")).upper()
            cvss = d.get("cvss", "")
            if verdict == "CONFIRMED" or ok == "YES":
                return True, f"CONFIRMED by coder56_verifier{f' (CVSS {cvss})' if cvss else ''}"
            return False, f"{verdict or 'NOT_A_VULN'} by coder56_verifier — {d.get('reason', '')}"
    return False, ""


# =============================================================================
# Recon-level findings (the f6182182 "2/9" defect): the agent's final report
# carries a markdown table of security misconfigurations (M-001..M-NNN) that
# never went through the verifier gate — and both the engagement merge
# (_merge_confirmed_findings_into_engagement, verified-only) and the phase-report
# parser (_RE_PHASE_FINDING_HEAD, F#/D# headers only) drop them, so real
# recon-level issues never reach the client deliverable. The extractor below
# parses that table (and the same shape in MEMORY.md recon ledgers) so recon
# findings flow into the engagement with HONEST provenance: verified=false,
# severity from the table, severity capped at LOW (recon-level by construction —
# if it were exploitable it would have been verifier-gated).
# =============================================================================

# | M-001 | Title text with (anything) | CWE-693 | LOW |
_RE_RECON_ROW = re.compile(
    r"^\s*\|\s*([A-Z]{1,3}-\d{1,3})\s*\|\s*([^|]+?)\s*\|\s*(CWE-\d+)[^|]*\|\s*"
    r"(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\|?\s*$", re.I)
_RE_RECON_SECTION = re.compile(
    r"misconfiguration|recon[- ]level|security\s+issue|recon\s+issue", re.I)

# Numeric severity the merge/draft paths already use (mirrors _severity_for caps)
_RECON_SEV_CAP = {"critical": "low", "high": "low", "medium": "low",
                  "low": "low", "info": "info"}


def _parse_recon_table(text: str) -> List[Dict[str, str]]:
    """Yield {id,title,cwe,severity} rows from a markdown recon/misconfig table
    inside `text`. Only rows under (or immediately after) a section heading that
    smells like 'Security Misconfigurations (Recon-Level)' — never from arbitrary
    tables (coverage matrices, phase checklists) elsewhere in the report."""
    rows: List[Dict[str, str]] = []
    in_section = False
    gap_since_heading = 0
    for ln in (text or "").splitlines():
        if ln.lstrip().startswith("#"):
            in_section = bool(_RE_RECON_SECTION.search(ln))
            gap_since_heading = 0
            continue
        m = _RE_RECON_ROW.match(ln)
        if in_section and m:
            rows.append({"id": m.group(1).upper(),
                         "title": m.group(2).strip().strip("`*"),
                         "cwe": m.group(3).upper(),
                         "severity": m.group(4).upper()})
            gap_since_heading = 0
        elif in_section and ln.strip() and not ln.lstrip().startswith("|"):
            # Left the table for prose: a single prose line closes the section
            # (markdown tables don't interleave with paragraphs; anything after
            # is a different table and must not ride along).
            in_section = False
    return rows


def _extract_recon_findings(run_id: str) -> List[Dict[str, Any]]:
    """FindingCreate-shaped recon-level findings from the run's final_report.md
    (authoritative) and memory/MEMORY.md (fallback when the report wasn't
    written). All rows land as verified=false — the verifier never saw them —
    and severity is capped at LOW so recon rows can never outrank a
    verifier-CONFIRMED finding. Evidence cites the source file + line so the
    client can audit the provenance."""
    run_dir = OUTPUTS_DIR / run_id
    out: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for src_name in ("final_report.md", "memory/MEMORY.md"):
        src = run_dir / src_name
        if not src.exists():
            continue
        try:
            text = src.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        src_label = "final report" if src_name.startswith("final") else "agent memory ledger"
        for row in _parse_recon_table(text):
            if row["id"] in seen_ids:
                continue
            seen_ids.add(row["id"])
            sev = _RECON_SEV_CAP.get(row["severity"].lower(), "low")
            title_txt = f"{row['id']}: {row['title']}"
            out.append({
                "run_id": run_id,
                "title": title_txt[:200],
                "severity": sev,
                "cvss": None,
                "affected_asset": "",
                "description": f"{row['title']} (recon-level security misconfiguration, {row['cwe']}).",
                "impact": "",
                "evidence": f"Recorded as {row['id']} ({row['cwe']}, severity {row['severity']} per the agent's own {src_label}) in /outputs/{run_id}/{src_name}. Recon-level: established during enumeration, not verifier-gated.",
                "recommendation": "",
                "status": "open",
                "verified": False,
                "verifier_verdict": "",
                "commands": [],
                "cwe_hint": row["cwe"].lower(),
            })
        if out:
            # final_report.md is authoritative — stop once it yielded rows.
            break
    return out


def _extract_findings_from_phase_reports(run_id: str) -> List[Dict[str, Any]]:
    """Parse the real findings out of the phase reports (run.json ->
    phase_runtime[].result). Returns FindingCreate-shaped dicts. Authoritative
    source: guarantees the agent's actual F#/D# findings reach the reporter
    instead of the memory-note scrapings the emission log yields. Each finding is
    marked unverified unless a matching coder56_verifier VERDICT confirms it."""
    meta = _read_run_meta(run_id)
    findings: List[Dict[str, Any]] = []
    seen: set = set()
    for pr in (meta.get("phase_runtime") or []):
        text = pr.get("result") or ""
        if not isinstance(text, str) or len(text) < 40:
            continue
        for m in _RE_PHASE_FINDING_HEAD.finditer(text):
            fid, title_raw = m.group(1), m.group(2).strip().strip(" |`*")
            start = m.end()
            nxt = _RE_PHASE_FINDING_HEAD.search(text, start)
            block = text[start:(nxt.start() if nxt else len(text))]
            cwem = re.search(r"(CWE-\d+)", title_raw + " " + block[:200], re.I)
            cwe = cwem.group(1).upper() if cwem else ""
            title = re.sub(r"\s*\(CWE-\d+[^)]*\)\s*$", "", title_raw).strip(" `*")
            title = re.sub(r"\s*[—\-–]\s*$", "", title).strip()
            if not title or len(title) < 6:
                continue
            dedup_key = fid.lower() if fid.lower().startswith("f") else title[:60].lower()
            if dedup_key in seen:
                continue
            vector = _phase_table_row(block, "Vector")
            flaw = _phase_table_row(block, "Flaw")
            proof = _phase_table_row(block, "Proof")
            impact_txt = _phase_table_row(block, "Impact")
            cvss = None
            cm = _RE_PHASE_CVSS.search(block)
            if cm:
                try:
                    cvss = float(cm.group(1))
                except ValueError:
                    cvss = None
            epm = _RE_ENDPOINT.search(f"{vector} {title}")
            hpm = _RE_HOSTPORT.search(f"{vector} {title}")
            asset = (hpm.group(1) if hpm else "")
            if epm:
                asset = (asset + " " + epm.group(0)).strip()
            desc = re.sub(r"\s+", " ", (flaw or vector or title)).strip()
            endpoint = epm.group(0) if epm else ""
            verified, verdict_line = _verifier_verdict_for(run_id, endpoint, title)
            sev = _severity_for(cvss, verdict_line, f"{desc} {impact_txt}", verified)
            impact, reco = _impact_reco(f"{desc} {impact_txt}")
            if impact_txt:
                impact = impact_txt[:400]
            findings.append({
                "run_id": run_id,
                "title": title[:200],
                "severity": sev,
                "cvss": cvss,
                "affected_asset": asset[:200],
                "verified": verified,
                "verifier_verdict": verdict_line,
                "commands": [],
                "evidence": re.sub(r"\s+", " ", (proof or desc)).strip()[:700],
                "description": desc[:700],
                "impact": impact,
                "recommendation": reco,
                "status": "open",
                "cwe_hint": cwe,
            })
            seen.add(dedup_key)
    return findings


def _enrich_findings_from_emissions(findings: List[Dict[str, Any]],
                                    emissions: List[Dict[str, Any]]) -> None:
    """Copy repro commands (and any verifier CONFIRMED status) from emission
    candidates onto phase-report findings that share the same endpoint path —
    the emission log has the exact PoC commands the phase prose lacks."""
    by_ep: Dict[str, Dict[str, Any]] = {}
    for e in emissions:
        epm = _RE_ENDPOINT.search(f"{e.get('affected_asset', '')} {e.get('title', '')}")
        if epm:
            by_ep.setdefault(epm.group(0).lower(), e)
    for f in findings:
        epm = _RE_ENDPOINT.search(f"{f.get('affected_asset', '')} {f.get('title', '')}")
        e = by_ep.get(epm.group(0).lower()) if epm else None
        if not e:
            continue
        if e.get("commands") and not f.get("commands"):
            f["commands"] = [c for c in e["commands"][:40] if c]
        if e.get("verified") and not f.get("verified"):
            f["verified"] = True
            f["verifier_verdict"] = e.get("verifier_verdict") or f.get("verifier_verdict", "")


# --- Findings drafting (deterministic, agent-free). ---
# The draft is produced entirely in-process — no opencode session, no LLM call.
# The reporter used to be a coder56_reporter opencode agent whose only job was to
# read+concatenate the findings the backend had ALREADY extracted; that was a
# ~600s round-trip plus a sandbox/timeout/502 failure surface for a json merge.
# The backend now returns the merged findings directly.
#
# Sources, in priority order:
#   1. coder56_verifier VERDICT records  (/outputs/<run_id>/verifier/*.jsonl)
#      — the authoritative, false-positive-free record of what was proven: claim,
#      route, verdict, OK-TO-REPORT, CVSS, and the verification reasoning.
#   2. guardrail emission log             (/outputs/<run_id>/guardrail/verdicts.ndjson)
#      — the agent's structured CLAIM/FINDING/VERDICT writes (catches findings the
#      verifier never formally gated) and the source of the exact repro commands.
# The phase-report narrative (run.json phase_runtime[].result) is intentionally
# NOT mined for findings: it is dense prose mixing recon, negative results, and
# "not a vuln" sections — a rich false-positive source. It is preserved verbatim
# in the report's Evidence Appendix instead. Candidates merge within a run, then
# de-duplicate ACROSS runs (the same vuln is re-found across OWASP categories).


def _title_from_claim(claim: str, route: str) -> str:
    """Short professional title from a verifier CLAIM sentence: cut at an early
    em-dash/dash clause boundary, truncate at a word boundary, append the route
    if it is not already present."""
    c = re.sub(r"\s+", " ", (claim or "")).strip()
    for sep in (" — ", " – ", " - "):
        i = c.find(sep)
        if 0 < i <= 130:
            c = c[:i].strip()
            break
    title = c[:120]
    if len(c) > 120:
        title = c[:120].rsplit(" ", 1)[0]
    if route and route not in title:
        title = f"{title} ({route})"
    return title[:200]


def _extract_verifier_findings(run_id: str) -> List[Dict[str, Any]]:
    """Findings anchored on coder56_verifier's machine-readable VERDICT records
    (/outputs/<run_id>/verifier/<slug>.jsonl). Each VERDICT carries the claim, the
    route, the verdict (CONFIRMED / NOT_A_VULN), OK-TO-REPORT, CVSS, and the
    verification reasoning — the authoritative source for what was proven. Exact
    repro commands are recovered from the run's guardrail command log."""
    vdir = OUTPUTS_DIR / run_id / "verifier"
    if not vdir.exists():
        return []
    verdicts = _read_verdicts_full(run_id)
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for jf in sorted(vdir.glob("*.jsonl"), key=lambda p: p.name):
        # Parse line-by-line and SALVAGE malformed lines instead of skipping
        # them (do NOT abandon the whole file either). The verifier routinely
        # hand-writes records with unescaped inner quotes, invalid \xNN
        # escapes, trailing shell garbage, or truncation — the 2026-08-25
        # audit found a CONFIRMED 4.3 MEDIUM VERDICT lost to exactly this
        # (unescaped quotes in evidence_file), plus the owasp2 A01 BOLA lost
        # to a whole-file parse abandon before per-line parsing existed.
        # _read_verifier_records applies strict parse -> escape repair ->
        # raw_decode -> tolerant scan, in that order.
        recs, _bad = _read_verifier_records(jf)
        verdict = next((d for d in recs if d.get("step") == "VERDICT"), None)
        if not verdict:
            continue
        v = str(verdict.get("verdict", "")).upper()
        ok = str(verdict.get("ok_to_report", "")).upper()
        confirmed = (v == "CONFIRMED" or ok == "YES")
        claim = str(verdict.get("claim") or verdict.get("route") or jf.stem)
        route = str(verdict.get("route") or "")
        reason = str(verdict.get("reason") or "")
        intended = str(verdict.get("intended_behavior") or "")
        # 8c2f1a postmortem (defect 1 companion): the `seen` identity used to be
        # `route or claim[:80]`, which DROPPED the second of two genuinely
        # distinct verdicts sharing one route (order_by SQLi + group_by SQLi on
        # /api/resource/User) before dedup ever ran. Identity is now the
        # finding's own dedup key (METHOD|path|CWE|role|param) with the slug
        # appended — per-file unique, so restatements across files still merge
        # later via _dedup_key while two distinct defects on one route survive.
        try:
            ident = f"{_dedup_key({'title': claim, 'affected_asset': route, 'description': reason})}|{jf.stem}"
        except Exception:
            ident = f"{claim[:80]}|{jf.stem}"
        if ident in seen:
            continue
        seen.add(ident)
        cvss = None
        # canonical shape is "<score> <band>" (leading number), but salvaged
        # verdicts from real runs also carry "CVSS:3.1/<vector> => 9.1 =>
        # CRITICAL" — read the arrow-delimited score or a number directly
        # followed by a band word, never the vector's own "3.1".
        cvss_raw = str(verdict.get("cvss") or "")
        m = (re.match(r"\s*([0-9]+(?:\.[0-9]+)?)", cvss_raw)
             or re.search(r"=>\s*([0-9]+(?:\.[0-9]+)?)\s*=>", cvss_raw)
             or re.search(r"([0-9]+(?:\.[0-9]+)?)\s*"
                          r"(?:NONE|LOW|MEDIUM|HIGH|CRITICAL)", cvss_raw, re.I))
        if m:
            try:
                cvss = float(m.group(1))
            except ValueError:
                cvss = None
        cwe_m = re.search(r"(CWE-\d+)", f"{claim} {reason} {verdict.get('cvss', '')}")
        cwe = cwe_m.group(1) if cwe_m else ""
        if confirmed:
            verified, verdict_line = True, f"CONFIRMED by coder56_verifier — OK TO REPORT: {ok or 'YES'}"
        else:
            verified = False
            verdict_line = f"{v or 'NOT_A_VULN'} by coder56_verifier" + (f" — {reason[:160]}" if reason else "")
        body = f"{claim}{' — ' + reason if reason else ''}"
        hp = _RE_HOSTPORT.search(f"{reason} {claim}")
        epm = _RE_ENDPOINT.search(f"{route} {claim} {reason}")
        asset = (f"{hp.group(1)} " if hp else "") + (epm.group(0) if epm else route)
        sev = _severity_for(cvss, verdict_line, body, verified)
        commands = _literal_commands(f"{claim} {reason} {route}", route or claim, [], verdicts)
        impact, reco = _impact_reco(body)
        out.append({
            "run_id": run_id,
            "title": _title_from_claim(claim, route),
            "severity": sev,
            "cvss": cvss,
            "affected_asset": asset.strip()[:300],
            "verified": verified,
            "verifier_verdict": verdict_line,
            "commands": commands,
            "evidence": (reason or intended or claim)[:700],
            "description": body[:700],
            "impact": impact,
            "recommendation": reco,
            "status": "open",
            "cwe_hint": cwe,
            # Propagate the explicit defect-family label (§2.2(c)) so the
            # cross-verdict retraction backstop can bucket findings on the same
            # stable key as their verdict records. Empty when the verifier omitted
            # it; the retraction bucket then falls back to family@method|path.
            "defect": str(verdict.get("defect") or "").strip().lower(),
            "route": route,
        })
    return out


def _normalize_path(path: str) -> str:
    """Normalize a route for fingerprinting: drop query/protocol/host, strip a
    trailing slash, collapse numeric/hex/uuid path SEGMENTS to :param, lowercase.
    CRITICAL: only individual id-like segments collapse — the resource PREFIX is
    preserved, so /distributions/:param/finalize != /donation-receptions/:param/finalize."""
    if not path:
        return ""
    p = path.split("?")[0].strip()
    p = re.sub(r"^[a-z]+://[^/]+", "", p, flags=re.I)
    segs: List[str] = []
    for seg in p.split("/"):
        if not seg:
            continue
        if (re.fullmatch(r"\d+", seg)                      # 123
                or re.fullmatch(r"[0-9a-fA-F]{8,}", seg)    # hex >= 8
                or re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]+", seg)):  # uuid
            seg = ":param"
        else:
            seg = seg.lower()
        segs.append(seg)
    norm = "/" + "/".join(segs)
    return norm.rstrip("/") or "/"


def _parse_pipe_record(s: str) -> Optional[Dict[str, str]]:
    """Parse a `k=v|k=v|...` pipe-delimited agent memory record (TESTED|,
    SURFACE_ITEM|, PRINCIPAL|, THREAT_MODEL|, TARGET_IDENTITY|) into a dict.
    None if no key=value pairs found."""
    rec: Dict[str, str] = {}
    for part in s.split("|"):
        if "=" in part:
            k, _, v = part.partition("=")
            rec[k.strip()] = v.strip()
    return rec or None


# Map a vuln class (detected from the finding's prose) to its canonical CWE. The
# agent tags the CWE on a finding inconsistently — two restatements of the SAME
# issue often carry the literal "CWE-307" in only one (the other just says "no
# rate-limiting"). A dedup key built from the raw tag then fails to merge them
# (the owasp2 login-rate-limit and donor-email-exposure duplicate pairs). Inferring
# the canonical CWE from the class makes the key stable regardless of whether the
# literal tag was emitted. Order matters: more specific access-control classes
# (BOLA/IDOR/BFLA) are matched BEFORE the generic data-exposure class, so a BOLA
# claim that happens to mention "donor_email PII" keys as CWE-639, not CWE-200 —
# keeping the access-control finding distinct from the over-exposure finding on
# the same route.
_VULNCLASS_TO_CWE: List[tuple] = [
    (re.compile(r"\b(rate[- ]?limit|lockout|anti[- ]?automation|brute[- ]?force)\b", re.I), "cwe-307"),
    (re.compile(r"\b(idor|bola|broken[- ]?access|priv(?:ilege)?\s*esc|access[- ]?control|cross[- ]?tenant)\b", re.I), "cwe-639"),
    (re.compile(r"\b(bfla|function[- ]?level|broken[- ]?function)\b", re.I), "cwe-285"),
    (re.compile(r"\b(session\s+(?:expir|invalid|revoc)|no\s+server[- ]?side\s+(?:revocation|invalidation)|non[- ]?revocable|token\s+invalidation|jwt\s+expir)\b", re.I), "cwe-613"),
    (re.compile(r"\b(password\s+policy|weak\s+password|min(?:imum)?[- ]?length\s+\d)\b", re.I), "cwe-521"),
    (re.compile(r"\b(timing[- ]?(?:based|sensitive)?\s*(?:user|account)?\s*enumerat|username\s+enumerat)\b", re.I), "cwe-208"),
    (re.compile(r"\b(sql(?:i|injection)|injection)\b", re.I), "cwe-89"),
    (re.compile(r"\b(?:input[- ]?validation|accept(?:ing|s)\s+fabricat\w*|no\s+server[- ]?side\s+(?:format|length))", re.I), "cwe-20"),
    (re.compile(r"\bxss\b|cross[- ]?site\s+script", re.I), "cwe-79"),
    (re.compile(r"\bssrf\b|server[- ]?side\s+request\s+forge", re.I), "cwe-918"),
    (re.compile(r"\b(expos(?:e|ure)|over[- ]?fetch|excessive\s+data|sensitive\s+data|donor_email|plaintext|pii)\b", re.I), "cwe-200"),
]


def _canonical_cwe(f: Dict[str, Any]) -> str:
    """The finding's canonical CWE: the explicit tag if present, else inferred
    from its vuln-class vocabulary (see _VULNCLASS_TO_CWE). '' if neither."""
    raw = (str(f.get("cwe_hint") or "")).split(",")[0].strip().lower()
    if raw.startswith("cwe-"):
        return raw
    blob = " ".join(str(f.get(k) or "") for k in
                    ("title", "title_raw", "description", "body", "affected_asset"))
    # An explicit literal tag in the prose ("Stored CSV/Formula Injection
    # (CWE-1236) ...") beats vocabulary inference: without this, a finding
    # stored without its cwe_hint re-infers cwe-89 from the word "Injection"
    # while its verifier candidate keys on the literal cwe-1236 — asymmetric
    # _dedup_key, one new duplicate per harvest pass (8c2f1a postmortem).
    m = re.search(r"\bcwe-\d{1,5}\b", blob, re.I)
    if m:
        return m.group(0).lower()
    for pat, cwe in _VULNCLASS_TO_CWE:
        if pat.search(blob):
            return cwe
    return ""


# Parameter / injection-point dimension (erpnext 8c2f1a postmortem defect 1).
# Two genuinely DISTINCT findings on one route can differ ONLY by the parameter
# they inject into — SQLi in `order_by` vs SQLi in `group_by` on
# /api/resource/User — for which METHOD|path|CWE|role are all identical, so both
# the auto-merge and the draft merge collapsed them into ONE finding (base's
# order_by title + the longer group_by description: the operator could not tell
# them apart and re-added the duplicate). The forms below pull the parameter
# identifier out of the finding's own evidence; bare-word recognition is limited
# to a small, unambiguous vocabulary so ordinary prose never invents a dimension.
_RE_PARAM_ASSIGNED = re.compile(
    r"\bparam(?:eter)?s?\s*[:=]\s*[\"']?([A-Za-z_][A-Za-z0-9_.\-]{0,40})", re.I)
_RE_PARAM_NAMED = re.compile(
    r"\b(?:the\s+)?([A-Za-z_][A-Za-z0-9_.\-]{0,40})\s+parameter\b", re.I)
_RE_PARAM_QUERY = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,40})=", re.I)
_RE_PARAM_KNOWN = re.compile(r"\b(order[\s_]+by|group[\s_]+by|debug|searchfield)\b", re.I)
# "<entity> <field_name> field" phrasing ("Customer customer_name field") — the
# 8c2f1a CSV-injection finding names its injection point this way and none of
# the forms above matched, collapsing the param dimension to ''. Tried LAST so
# existing derivable params are unchanged.
_RE_PARAM_FIELD = re.compile(r"\b([a-z_][a-z0-9_]{1,40})\s+field\b")


def _param_key(f: Dict[str, Any]) -> str:
    """Normalized parameter / injection-point identifier for a finding.

    '' when none is derivable — findings without a parameter token then keep the
    previous (empty-dimension) key behaviour, so a restatement that omits the
    parameter still merges with one that names it. The explicit multi-word
    vocabulary (_RE_PARAM_KNOWN) is tried FIRST so "order_by parameter" and
    "the order by parameter" normalize identically (the single-token forms would
    otherwise capture the trailing word "by" from the spaced spelling)."""
    blob = " ".join(str(f.get(k) or "") for k in
                    ("title", "title_raw", "description", "body",
                     "affected_asset", "evidence", "route"))
    m = _RE_PARAM_KNOWN.search(blob)
    if m:
        return re.sub(r"\s+", "_", m.group(1).lower())
    for rx in (_RE_PARAM_ASSIGNED, _RE_PARAM_QUERY, _RE_PARAM_NAMED):
        m = rx.search(blob)
        if m:
            return re.sub(r"[^a-z0-9_]+", "_", m.group(1).lower().strip("_")) or ""
    m = _RE_PARAM_FIELD.search(blob)
    if m:
        return m.group(1).lower()
    return ""


def _dedup_key(f: Dict[str, Any]) -> str:
    """Stable identity for one issue across sources AND runs.

    Canonical key = METHOD | normalized_path | canonical_CWE | role | param,
    computed the SAME way for every candidate (verifier-anchored or emission).
    Previously the strict METHOD|PATH|CWE|role fingerprint was used only when
    method AND cwe were both present, with a noisy vuln-class|endpoint fallback
    otherwise — and since the agent tags CWE inconsistently, two restatements of
    one finding routinely landed on different keys and survived as duplicates
    (the owasp2 login-rate-limit and donor-email-exposure pairs). Using the
    _canonical_cwe (inferred when the literal tag is missing) makes the key
    stable so duplicates collapse, while METHOD/role still keep BFLA-vs-BOLA and
    different-attacker-role distinct. The trailing PARAM dimension (8c2f1a
    postmortem) keeps two distinct injection points on one route — order_by vs
    group_by SQLi — separate; it is empty whenever no parameter is derivable, so
    parameter-less restatements of one finding still merge as before.

    Falls back to a normalized title only when no endpoint path is derivable.

    RECON ROWS are keyed on their stable M-NNN id (up front): the extractor
    titles carry the report's backticks/spacing verbatim while an operator or
    manual backfill may phrase the same row differently, and without the id key
    every harvest re-appends a near-duplicate (observed live on 5139ebbf3fe7
    after the first patched restart: 6/7 rows duplicated)."""
    m_id = re.match(r"^([A-Z]{1,3}-\d{1,3}):\s", str(f.get("title") or ""))
    if m_id:
        return f"recon|{m_id.group(1).upper()}"
    blob = f"{f.get('title') or f.get('title_raw') or ''} {f.get('affected_asset', '')} {f.get('description', '')}"
    mm = _RE_METHOD.search(blob)
    method = mm.group(1).upper() if mm else ""
    epm = _RE_ENDPOINT.search(f"{f.get('affected_asset', '')} {f.get('title') or f.get('title_raw') or ''}")
    path = _normalize_path(epm.group(0)) if epm else ""
    # Junk single-token asset ("/Formula" — _RE_ENDPOINT grabbed the capitalized
    # word "Formula" out of a title like "Stored CSV/Formula Injection"): when
    # the derived path is one bare segment but the prose names a real multi-
    # segment route, prefer the real route. Conservative: the override only
    # fires for single-segment paths, so genuine /login-style endpoints and all
    # properly extracted paths keep their existing keys (8c2f1a postmortem).
    if path and "/" not in path.lstrip("/") and " " not in path:
        desc = f"{f.get('description', '')} {f.get('route', '')} {f.get('evidence', '')}"
        # First multi-segment route in the prose wins (a single-token path can
        # ALSO appear mid-prose — "Stored CSV/Formula Injection in POST
        # /api/resource/Customer" — so search() alone may re-find the junk).
        for better in _RE_ENDPOINT.finditer(desc):
            cand = _normalize_path(better.group(0))
            if cand and "/" in cand.lstrip("/"):
                path = cand
                break
    cwe = _canonical_cwe(f)
    rm = re.search(r"\b(ROLE_[A-Z_]+)\b", blob)
    role = rm.group(1).lower() if rm else ""
    if path:
        return f"{method}|{path}|{cwe}|{role}|{_param_key(f)}"
    return re.sub(r"\s+", " ", f.get("title") or f.get("title_raw") or "").strip().lower()[:60]


def _merge_findings(base: Dict[str, Any], other: Dict[str, Any]) -> Dict[str, Any]:
    """Field-level merge of two findings for the same issue (across sources or
    runs). `base` keeps identity (title/asset/source run/owasp); `other` fills
    gaps and upgrades — verified wins, commands union, higher CVSS, longer prose.
    Run/owasp provenance accumulates into lists for the report."""
    out = dict(base)
    if not out.get("verified") and other.get("verified"):
        # CONFIRMED > REFUTED/INCONCLUSIVE precedence (postmortem defect #2): a real
        # verifier VERDICT confirming an issue that an earlier restatement demoted to
        # info/NOT_A_VULN must define the finding — its boolean flag AND its verdict,
        # cvss, and severity. Without recomputing severity/cvss here, a confirmed
        # finding merging into a refuted base kept the base's severity=info.
        out["verified"] = True
        out["verifier_verdict"] = other.get("verifier_verdict") or out.get("verifier_verdict", "")
        if other.get("cvss") is not None:
            out["cvss"] = other["cvss"]
        if other.get("severity"):
            out["severity"] = other["severity"]
    cmds = list(out.get("commands") or [])
    for c in (other.get("commands") or []):
        if c and c not in cmds:
            cmds.append(c)
    out["commands"] = cmds[:40]
    try:
        if (other.get("cvss") or 0) > (out.get("cvss") or 0):
            out["cvss"] = other["cvss"]
    except (TypeError, ValueError):
        pass
    for fld in ("description", "impact", "evidence", "recommendation"):
        if len(str(other.get(fld) or "")) > len(str(out.get(fld) or "")):
            out[fld] = other[fld]
    for src in ("discovered_via_run_id", "owasp_id"):
        vals = list(out.get(f"_{src}s") or ([out.get(src)] if out.get(src) else []))
        if other.get(src):
            vals.append(other.get(src))
        out[f"_{src}s"] = sorted({str(v) for v in vals if v})
    return out


# Verdicts that, appearing LATER on the same defect bucket than a CONFIRMED,
# contradict it and trigger retraction of the earlier confirmed finding.
_RETRACTION_VERDICTS = {"NOT_A_VULN", "INCONCLUSIVE", "NOT_CONFIRMABLE"}


def _verdict_defect_bucket(rec: Dict[str, Any]) -> str:
    """Stable, SCOPEd defect-bucket key for cross-verdict retraction. GENERIC for
    any vuln class — NOT crypto/auth-specific. Bucket = the explicit `defect`
    label (the kebab family the verifier records, e.g. `jwt-key-confusion`,
    `idor`, `bfla`, `sqli`); when no explicit label exists, fall back to
    `<inferred-family>@<METHOD>|<normalized-path>` so two genuinely-distinct
    defects on the same route do NOT collapse into one bucket (the false-retraction
    risk a loose keyword bag would create). The route component is always present
    in the fallback so the bucket never spans routes."""
    defect = str(rec.get("defect") or "").strip().lower()
    if defect:
        return defect
    # Fallback family: infer from the canonical CWE (or the verdict's own class
    # tokens) so a BOLA and a data-exposure on the same route stay distinct.
    family = ""
    cwe = str(rec.get("cwe_hint") or rec.get("cwe") or "").strip().lower()
    if cwe:
        family = cwe
    else:
        blob = " ".join(str(rec.get(k) or "") for k in
                        ("claim", "route", "reason", "title", "description")).lower()
        cwe_inferred = _canonical_cwe({"title": rec.get("claim", ""),
                                       "description": rec.get("reason", ""),
                                       "affected_asset": rec.get("route", "")})
        if cwe_inferred:
            family = cwe_inferred
        else:
            # Last resort: a coarse class token from the prose, else 'unknown'.
            fm = re.search(r"\b(idor|bola|bfla|sqli|sql[- ]?injection|ssrf|xss|"
                           r"cmd[- ]?injection|mass[- ]?assignment|jwt|auth|crypto|"
                           r"deserializ|rate[- ]?limit)\b", blob)
            family = fm.group(1) if fm else "unknown"
    # Route component: METHOD | normalized-path (empty route => the bucket is the
    # family alone; still scope-safe because the family is defect-specific).
    route_blob = str(rec.get("route") or rec.get("affected_asset") or
                     rec.get("title") or rec.get("claim") or "")
    mm = _RE_METHOD.search(route_blob)
    method = mm.group(1).upper() if mm else ""
    epm = _RE_ENDPOINT.search(route_blob)
    path = _normalize_path(epm.group(0)) if epm else ""
    route_key = f"{method}|{path}" if path else ""
    return f"{family}@{route_key}" if route_key else family


def _retract_contradicted_findings(engagement: Dict[str, Any],
                                   run_id: str) -> Dict[str, str]:
    """GENERIC cross-verdict retraction backstop (§2.3(ii)). For ONE run, read
    EVERY verdict shape in /outputs/<run_id>/verifier/ — both *.jsonl (line-by-line
    VERDICT records, the shape _extract_verifier_findings globs) AND *.json (the
    *-verdict.json / *verdict*.json downgrade files _extract_verifier_findings
    MISSES, which is how the de1e6112 jwt-hs512 INCONCLUSIVE downgrade slipped past
    the confirmed jwt-hmac-key-confusion HIGH). Bucket by explicit `defect` label
    else defect-family@normalized-method-path (see _verdict_defect_bucket). If a
    bucket holds a LATER NOT_A_VULN / INCONCLUSIVE / NOT_CONFIRMABLE alongside an
    earlier CONFIRMED, the confirmed finding must be retracted.

    Returns a {bucket_key: retraction_note} map for buckets whose confirmed
    finding is contradicted by a later weaker verdict. _draft_findings_inprocess
    applies the downgrade (verified=False, severity='info', annotated
    verifier_verdict) to any merged finding in a retracted bucket — _merge_findings
    only ever upgrades, so this is the missing downgrade path. Works for ANY defect
    family, not only crypto/auth."""
    if not run_id:
        return {}
    vdir = OUTPUTS_DIR / run_id / "verifier"
    if not vdir.exists():
        return {}
    # Collect verdict records from BOTH file shapes, preserving a stable
    # file-then-line ordering so 'later' is well-defined. *.jsonl: each non-blank
    # line is a JSON record; pick the step=='VERDICT' one. *.json: the whole file
    # is one JSON object (or a list); if it carries verdict/ok_to_report/claim
    # fields, treat the object itself (or each element) as a verdict record.
    seq = 0
    bucket_records: Dict[str, List[Dict[str, Any]]] = {}

    def _ingest(rec: Any) -> None:
        nonlocal seq
        if not isinstance(rec, dict):
            return
        is_verdict = (str(rec.get("step", "")).upper() == "VERDICT"
                      or "verdict" in rec
                      or "ok_to_report" in rec)
        if not is_verdict:
            return
        v = str(rec.get("verdict", "")).upper()
        ok = str(rec.get("ok_to_report", "")).upper()
        confirmed = (v == "CONFIRMED" or ok == "YES")
        if not confirmed and v not in _RETRACTION_VERDICTS:
            return  # only CONFIRMED + the weakening verdicts participate
        rec2 = dict(rec)
        rec2["_seq"] = seq
        rec2["_confirmed"] = confirmed
        rec2["_v"] = v or ("CONFIRMED" if confirmed else "")
        bk = _verdict_defect_bucket(rec2)
        if not bk:
            return
        bucket_records.setdefault(bk, []).append(rec2)
        seq += 1

    for jf in sorted(vdir.glob("*.jsonl"), key=lambda p: p.name):
        recs, _bad = _read_verifier_records(jf)
        for d in recs:
            _ingest(d)
    for jf in sorted(vdir.glob("*.json"), key=lambda p: p.name):
        try:
            text = jf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        try:
            parsed = json.loads(text)
        except Exception:
            continue
        if isinstance(parsed, list):
            for el in parsed:
                _ingest(el)
        else:
            _ingest(parsed)

    retracted: Dict[str, str] = {}
    for bk, recs in bucket_records.items():
        if not any(r.get("_confirmed") for r in recs):
            continue  # no confirmed finding in this bucket — nothing to retract
        if not any((not r.get("_confirmed")) and r.get("_v") in _RETRACTION_VERDICTS
                   for r in recs):
            continue  # no later weakening verdict — no contradiction
        # Order by sequence; a weaker verdict at a HIGHER sequence than any
        # confirmed one is a genuine later contradiction.
        ordered = sorted(recs, key=lambda r: r.get("_seq", 0))
        first_confirmed_seq = next((r.get("_seq", 0) for r in ordered if r.get("_confirmed")), None)
        weaker = next((r for r in ordered
                       if (not r.get("_confirmed")) and r.get("_v") in _RETRACTION_VERDICTS
                       and r.get("_seq", 0) >= (first_confirmed_seq or 0)), None)
        if weaker is None:
            continue
        wv = weaker.get("_v") or "INCONCLUSIVE"
        wslug = str(weaker.get("slug") or weaker.get("id") or weaker.get("route")
                    or bk)[:80]
        retracted[bk] = (
            f"retracted — later verdict {wslug} downgraded same defect ({bk}) to "
            f"{wv}; confirmed finding demoted to info (cross-verdict retraction "
            f"backstop)."
        )
    return retracted


def _draft_findings_inprocess(engagement: Dict[str, Any],
                              run_ids: List[str]) -> List[Dict[str, Any]]:
    """Gather FindingCreate-shaped findings for the given runs, agent-free. Per run:
    anchor on verifier VERDICT records, supplement with the guardrail emission
    log, merge duplicates within the run, then de-duplicate across runs and tag
    each finding with its OWASP category. Dicts carry the final shape (verified
    status parsed, exact commands pulled, prose derived) so _coerce_reporter_findings
    only normalizes."""
    plan = engagement.get("plan") or []
    run_to_owasp = {p.get("run_id"): (p.get("owasp_id"), p.get("title"))
                    for p in plan if p.get("run_id")}
    merged: Dict[str, Dict[str, Any]] = {}
    # §2.3(ii) cross-verdict retraction backstop, accumulated across runs. A
    # confirmed finding whose defect bucket (explicit `defect` label else
    # family@method|path) is contradicted by a LATER NOT_A_VULN/INCONCLUSIVE/
    # NOT_CONFIRMABLE verdict in the same bucket is downgraded to info. GENERIC
    # for any vuln class. _merge_findings only upgrades; this is the missing
    # downgrade path. Applied AFTER the cross-run merge so a contradicted finding
    # is retracted regardless of which run contributed it.
    retracted_buckets: Dict[str, str] = {}
    for rid in run_ids:
        try:
            retracted_buckets.update(_retract_contradicted_findings(engagement, rid))
        except Exception as exc:
            logger.warning("retract_contradicted[%s] failed: %s", rid, exc)
        by_key: Dict[str, Dict[str, Any]] = {}
        # Verifier (first) wins the within-run merge as `base`.
        for finds in (_extract_verifier_findings(rid), _extract_emission_findings(rid),
                      _extract_recon_findings(rid)):
            for f in finds:
                f = dict(f)
                f["run_id"] = rid
                f["discovered_via_run_id"] = rid
                oid, otitle = run_to_owasp.get(rid, ("", ""))
                f["owasp_id"] = oid
                f["owasp_title"] = otitle
                k = _dedup_key(f)
                prev = by_key.get(k)
                by_key[k] = _merge_findings(prev, f) if prev else f
        for f in by_key.values():
            k = _dedup_key(f)
            merged[k] = _merge_findings(merged[k], f) if k in merged else f
    if retracted_buckets:
        for f in merged.values():
            bk = _verdict_defect_bucket(f)
            note = retracted_buckets.get(bk)
            if not note:
                continue
            # DOWNGRADE (the path _merge_findings cannot take): demote the
            # confirmed finding to info + annotate the verdict that contradicted it.
            f["verified"] = False
            f["severity"] = "info"
            prior_vv = str(f.get("verifier_verdict") or "").strip()
            f["verifier_verdict"] = (f"{prior_vv} — {note}").strip(" —")[:500]
            logger.info("retract_contradicted: demoted finding '%s' (bucket=%s)",
                        str(f.get("title", ""))[:80], bk)
    return list(merged.values())


def _finding_is_refuted(f: Dict[str, Any]) -> bool:
    """True when the verifier explicitly REFUTED this finding (8c2f1a postmortem
    defect 3). Refuted = NOT a verifier-CONFIRMED finding AND the verifier left a
    negative verdict (NOT_A_VULN / INCONCLUSIVE / NOT_CONFIRMABLE / FALSE
    POSITIVE / ok_to_report=NO) on it. A merely UNVERIFIED claim (verified False,
    empty verdict — an emission claim the verifier never looked at) is NOT
    refuted and stays addable; only an explicit refutation excludes it."""
    if f.get("verified") is True:
        return False
    vv = str(f.get("verifier_verdict") or "").upper()
    if "OK TO REPORT: NO" in vv or "OK_TO_REPORT: NO" in vv:
        return True
    return any(tok in vv for tok in
               ("NOT_A_VULN", "INCONCLUSIVE", "NOT_CONFIRMABLE",
                "FALSE POSITIVE", "REFUTED", "RULED OUT"))


def _coerce_reporter_findings(raw_findings: List[Any]) -> List[Dict[str, Any]]:
    """Normalize merged finding dicts into FindingCreate-shaped suggestions. Does
    NOT raise on empty — a genuinely finding-less set is a valid (if uninteresting)
    result, surfaced by the caller with a note. Collapses the accumulated
    cross-run provenance lists back to scalars for the API."""
    out: List[Dict[str, Any]] = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        sev = str(raw.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        title = str(raw.get("title", "")).strip()
        if not title:
            continue
        cmds = raw.get("commands")
        cmds = ([str(c).strip() for c in cmds if str(c).strip()][:40]
                if isinstance(cmds, list) else [])
        cvss = raw.get("cvss")
        try:
            cvss = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None
        run_ids = raw.get("_discovered_via_run_ids") or ([raw.get("discovered_via_run_id")]
                                                        if raw.get("discovered_via_run_id") else [])
        owasp_ids = raw.get("_owasp_ids") or ([raw.get("owasp_id")] if raw.get("owasp_id") else [])
        out.append({
            "title": title[:200],
            "severity": sev,
            "cvss": cvss,
            "affected_asset": str(raw.get("affected_asset", ""))[:300],
            "description": str(raw.get("description", "")),
            "impact": str(raw.get("impact", "")),
            "evidence": str(raw.get("evidence", "")),
            "recommendation": str(raw.get("recommendation", "")),
            "status": "open",
            "verified": bool(raw.get("verified", False)),
            "verifier_verdict": str(raw.get("verifier_verdict", ""))[:500],
            "commands": cmds,
            "discovered_via_run_id": run_ids[0] if run_ids else None,
            "discovered_via_run_ids": run_ids,
            "owasp_id": owasp_ids[0] if owasp_ids else None,
            "owasp_ids": owasp_ids,
        })
    return out


def _surface_coverage(engagement_id: Optional[str],
                      findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """M10: coverage by SURFACE ITEM, not OWASP category. The phase worker appends a
    `TESTED|` line to the engagement's shared memory (_engagement_memory_path) for
    every endpoint x param x role x object-id x state it actually exercised; this
    mines those records (the producer↔consumer contract the phase prompt emits).
    Verifier VERDICT-confirmed routes not already in a TESTED| line are folded in so
    a confirmed finding is never absent from the matrix. `status` mirrors the phase
    contract: tested_confirmed | tested_negative | not_applicable | could_not_test |
    unverifiable — could_not_test/unverifiable are VISIBLE, never silently dropped
    (what A10 needed to say 'unverifiable (sink unreachable)' instead of 'no vuln')."""
    ledger: List[Dict[str, Any]] = []
    seen: set = set()
    mem = ""
    if engagement_id:
        try:
            mp = _engagement_memory_path(engagement_id)
            if mp.exists():
                mem = mp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            mem = ""
    for ln in mem.splitlines():
        ln = ln.strip()
        if not ln.startswith("TESTED|"):
            continue
        rec = _parse_pipe_record(ln[len("TESTED|"):])
        if not rec:
            continue
        method = (rec.get("method") or "").upper()
        path = rec.get("path") or ""
        key = f"{method}|{path}|{rec.get('params', '')}|{rec.get('role', '')}|{rec.get('object_id', '')}"
        if key in seen:
            continue
        seen.add(key)
        status = rec.get("status") or "tested_negative"
        ev = rec.get("evidence") or ""
        ledger.append({
            "method": method,
            "path": path,
            "params": [p for p in rec.get("params", "").split(",") if p],
            "role": rec.get("role", ""),
            "object_id": rec.get("object_id", ""),
            "cwe": rec.get("cwe", ""),
            "tested": status in ("tested_confirmed", "tested_negative"),
            "status": status,
            "run_id": rec.get("run_id", ""),
            "verified": status == "tested_confirmed",
            "evidence_file": "" if ev in ("", "none") else ev,
        })
    # Supplement: a verifier-CONFIRMED finding proves a surface item even if the
    # phase omitted its TESTED| line. Fold the finding's route in as tested_confirmed.
    for f in findings:
        if not f.get("verified"):
            continue
        blob = f"{f.get('title', '')} {f.get('affected_asset', '')} {f.get('verifier_verdict', '')}"
        mm = _RE_METHOD.search(blob)
        method = mm.group(1).upper() if mm else ""
        epm = _RE_ENDPOINT.search(f"{f.get('affected_asset', '')} {f.get('title', '')}")
        path = _normalize_path(epm.group(0)) if epm else ""
        if not path:
            continue
        key = f"{method}|{path}|||"
        if key in seen:
            continue
        seen.add(key)
        cwe = (f.get("cwe_hint") or "").split(",")[0].strip().lower()
        ledger.append({
            "method": method, "path": path, "params": [], "role": "",
            "object_id": "", "cwe": cwe, "tested": True,
            "status": "tested_confirmed",
            "run_id": f.get("discovered_via_run_id") or f.get("run_id") or "",
            "verified": True, "evidence_file": "",
        })
    return ledger


def _coverage(eng: Dict[str, Any], findings: List[Dict[str, Any]],
              engagement_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """OWASP Top-10 coverage matrix: per category, its lifecycle status, the run
    that materialized it, and how many drafted findings (verified + total) map to
    it. Only present for engagements that carry a `plan`. M10: when engagement_id is
    supplied, each row also carries the surface_items relevant to that category
    (mined from the engagement memory TESTED| ledger via _surface_coverage)."""
    plan = eng.get("plan") or []
    if not plan:
        return []
    surf_all = _surface_coverage(engagement_id, findings) if engagement_id else []
    # Bucket surface items to a category by matching the category's own finding routes.
    cat_paths: Dict[str, List[str]] = {}
    for f in findings:
        oid = f.get("owasp_id")
        if not oid:
            continue
        epm = _RE_ENDPOINT.search(f"{f.get('affected_asset', '')} {f.get('title', '')}")
        if epm:
            cat_paths.setdefault(oid, []).append(_normalize_path(epm.group(0)))
    counts: Dict[str, Dict[str, int]] = {}
    for f in findings:
        oid = f.get("owasp_id")
        if not oid:
            continue
        c = counts.setdefault(oid, {"findings": 0, "confirmed": 0})
        c["findings"] += 1
        if f.get("verified"):
            c["confirmed"] += 1
    rows: List[Dict[str, Any]] = []
    for p in plan:
        oid = p.get("owasp_id", "")
        c = counts.get(oid, {"findings": 0, "confirmed": 0})
        paths = cat_paths.get(oid, [])
        sitems: List[Dict[str, Any]] = []
        if paths and surf_all:
            for s in surf_all:
                sp = s.get("path", "")
                if any(sp == pp or sp.startswith(pp + "/") or pp.startswith(sp + "/") for pp in paths):
                    sitems.append(s)
        rows.append({
            "owasp_id": oid,
            "title": p.get("title", ""),
            "assessable": p.get("assessable", "black-box"),
            "status": p.get("status", "planned"),
            "run_id": p.get("run_id"),
            "findings": c["findings"],
            "confirmed": c["confirmed"],
            "surface_items": sitems,
        })
    return rows


@router.post("/engagements/{engagement_id}/findings/draft")
async def draft_findings(engagement_id: str, req: FindingsDraftRequest) -> Dict[str, Any]:
    """Draft findings from the engagement's on-disk run artifacts — fully
    deterministic and agent-free. Anchors on coder56_verifier VERDICT records,
    supplements with the guardrail emission log, de-duplicates across runs, tags
    each finding with its OWASP category, and returns an OWASP coverage matrix.

    Pass owasp_id to restrict the draft to one category's run. Returns suggestions
    (FindingCreate-shaped, incl. verifier status + exact repro commands) — NOT
    persisted; the operator reviews and saves the ones they keep."""
    _valid_token(engagement_id, "engagement_id")
    if req.owasp_id:
        _valid_token(req.owasp_id, "owasp_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    run_ids = eng.get("run_ids") or []
    if req.owasp_id:
        pr = next((p for p in (eng.get("plan") or []) if p.get("owasp_id") == req.owasp_id), None)
        run_ids = [pr["run_id"]] if pr and pr.get("run_id") else []
    live_runs = [rid for rid in run_ids if _read_run_meta(rid)]
    if not live_runs:
        return {"findings": [], "coverage": _coverage(eng, [], engagement_id),
                "coverage_ledger": _surface_coverage(engagement_id, []),
                "verifier_parse_alerts": [],
                "note": ("No run artifacts found yet"
                          + (f" for {req.owasp_id}" if req.owasp_id else "")
                          + " — run the engagement, then draft findings.")}

    findings = _coerce_reporter_findings(_draft_findings_inprocess(eng, live_runs))
    findings = _sort_findings(findings)
    # 8c2f1a postmortem defect 3: a REFUTED finding (verifier NOT_A_VULN /
    # ok_to_report=NO — e.g. the IDOR refutation) was offered as an "Add"-able
    # suggestion and the operator added it to the client-facing ledger. Refuted
    # findings are NOT addable; they are returned under `refuted` so the audit
    # trail (what was tested and ruled out) stays visible without being saved.
    refuted = [f for f in findings if _finding_is_refuted(f)]
    findings = [f for f in findings if not _finding_is_refuted(f)]
    # Serialization-loss alarm (2026-08-25 audit Rec 1): a candidate file whose
    # VERDICT record stays unparseable even after salvage is a possible lost
    # verdict — surface it to the operator instead of silently ignoring the
    # file (a CONFIRMED 4.3 MEDIUM vanished exactly this way).
    parse_alerts: List[str] = []
    for rid in live_runs:
        for alert in _verifier_parse_alerts(rid):
            parse_alerts.append(f"[{rid}] {alert}")
            logger.warning("verifier_parse_alert[%s] %s", rid, alert)
    coverage = _coverage(eng, findings, engagement_id)
    coverage_ledger = _surface_coverage(engagement_id, findings)
    confirmed = sum(1 for f in findings if f.get("verified"))
    if not findings:
        refuted_note = (f" ({len(refuted)} refuted finding(s) excluded — see 'refuted')"
                        if refuted else "")
        alert_note = (f" {len(parse_alerts)} verifier file(s) have NO parseable VERDICT "
                      f"record — see 'verifier_parse_alerts'."
                      if parse_alerts else "")
        return {"findings": [], "refuted": refuted, "coverage": coverage,
                "coverage_ledger": coverage_ledger,
                "verifier_parse_alerts": parse_alerts,
                "note": (f"No findings found across {len(live_runs)} run(s)"
                         + (f" for {req.owasp_id}" if req.owasp_id else "")
                         + " — neither verifier verdicts nor emission logs produced a CONFIRMED/claimed finding."
                         + refuted_note + alert_note)}
    note = (f"Drafted {len(findings)} finding(s) ({confirmed} verifier-confirmed) from "
            f"{len(live_runs)} run(s)" + (f" for {req.owasp_id}" if req.owasp_id else "")
            + " — review, edit, and save the ones you keep.")
    if refuted:
        note += (f" {len(refuted)} refuted finding(s) (NOT_A_VULN / ok_to_report=NO) excluded "
                 "from suggestions; see 'refuted' for the audit trail.")
    if parse_alerts:
        note += (f" WARNING: {len(parse_alerts)} verifier file(s) carry no parseable "
                 "VERDICT record — a verdict may have been lost to malformed "
                 "serialization; see 'verifier_parse_alerts'.")
    return {"findings": findings, "refuted": refuted, "coverage": coverage,
            "coverage_ledger": coverage_ledger, "note": note,
            "verifier_parse_alerts": parse_alerts}


# =============================================================================
# Report (self-contained, print-ready HTML)
# =============================================================================

# --- Client-ready report via the coder56_reporter (report-writer) agent. ---
# The agent AUTHORS the narrative (exec summary, business impact, plain-language
# explanations, remediation) from the structured findings + verifier evidence;
# the backend renders its JSON into print-ready HTML. Reuses the exact agent name
# "coder56_reporter" because guardrail.ts grants the read-only/no-network
# "reporter" profile only to that literal name.
REPORTWRITER_AGENT_NAME = "coder56_reporter"
REPORTWRITER_TIMEOUT_S = 900  # authoring ~20 findings' prose is heavier than a grep


def _best_verifier_file(run_id: Optional[str], finding: Dict[str, Any]) -> Optional[str]:
    """Pick the verifier/*.jsonl whose slug best matches a finding, so the
    report-writer agent can pull the full untruncated reasoning for context."""
    if not run_id:
        return None
    vdir = OUTPUTS_DIR / run_id / "verifier"
    if not vdir.exists():
        return None
    files = list(vdir.glob("*.jsonl"))
    if not files:
        return None
    blob = f"{finding.get('title', '')} {finding.get('affected_asset', '')}".lower()
    tokens = {t for t in re.split(r"[^a-z0-9]+", blob) if len(t) > 2}
    best, best_score = None, 0
    for f in files:
        score = sum(1 for t in tokens if t in f.stem.lower())
        if score > best_score:
            best, best_score = f, score
    return f"/outputs/{run_id}/verifier/{best.name}" if best else None


def _write_reportwriter_input(engagement_id: str, eng: Dict[str, Any],
                              findings: List[Dict[str, Any]]) -> Path:
    """Write the compact, agent-facing report input: engagement meta, the OWASP
    coverage matrix, and one block per finding (verified facts + a pointer to its
    verifier evidence file for richer context)."""
    rows = []
    for f in findings:
        rid = f.get("discovered_via_run_id") or f.get("run_id")
        # C5: preconditions derived (not fabricated) from the finding's auth/role
        # context; attack_path starts empty and the reporter infers chains from the
        # coverage_ledger (which surface items connect to which crown jewel).
        precond_bits: List[str] = []
        blob = f"{f.get('title', '')} {f.get('affected_asset', '')} {f.get('verifier_verdict', '')} {f.get('evidence', '')}"
        rm = re.search(r"\b(ROLE_[A-Z_]+)\b", blob)
        if rm:
            precond_bits.append(f"authenticated as {rm.group(1)}")
        if re.search(r"\bunauth|no[_ -]?auth|pre[_ -]?auth\b", blob, re.I):
            precond_bits.append("no authentication required")
        rows.append({
            "title": f.get("title", ""),
            "severity": f.get("severity", "medium"),
            "cvss": f.get("cvss"),
            "owasp_id": f.get("owasp_id") or "",
            "affected_asset": f.get("affected_asset", ""),
            "verified": bool(f.get("verified", False)),
            "verifier_verdict": f.get("verifier_verdict", ""),
            "technical_summary": f.get("description", ""),
            "evidence": f.get("evidence", ""),
            "commands": f.get("commands") or [],
            "evidence_file": _best_verifier_file(rid, f),
            "preconditions": "; ".join(precond_bits),
            "attack_path": [],
        })
    payload = {
        "engagement_name": eng.get("name", ""),
        "client": eng.get("client", ""),
        "target_scope": eng.get("target_scope", ""),
        "objective": eng.get("objective", ""),
        "roe": eng.get("roe", ""),
        "coverage": _coverage(eng, findings, engagement_id),
        "coverage_ledger": _surface_coverage(engagement_id, findings),
        "findings": rows,
    }
    path = OUTPUTS_DIR / "engagements" / f"{engagement_id}.reportwriter_input.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return path


async def _run_reportwriter_agent(engagement_id: str, eng: Dict[str, Any],
                                  findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Drive the coder56_reporter (report-writer) agent to author the client-ready
    report JSON. Raises HTTPException(502) on any failure — no silent empty."""
    from ..services.container_addr import get_container_address
    from ..services.opencode_client import (
        check_opencode_ready_async, create_session_async, send_prompt_async,
        get_session_messages_async, abort_session_async,
    )
    _write_reportwriter_input(engagement_id, eng, findings)
    in_container = f"/outputs/engagements/{engagement_id}.reportwriter_input.json"
    out_rel = f"engagements/{engagement_id}.report.json"
    out_host = OUTPUTS_DIR / out_rel
    out_container = f"/outputs/{out_rel}"
    # 8c2f1a postmortem defect 4c: do NOT unlink the previous report.json up
    # front. Unlinking at the start and then hanging left new input + stale HTML
    # + no JSON. The agent overwrites the output path itself; a previous report
    # is left intact if this pass fails, so the worst case is "old report", not
    # "no report". Completion is detected by the file CHANGING (or appearing),
    # so a leftover previous report cannot false-positive as fresh output.
    try:
        out_host.parent.mkdir(parents=True, exist_ok=True)
        _prev_stat = out_host.stat() if out_host.exists() else None
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Report setup failed (output path): {exc}")
    _prev_ident = (_prev_stat.st_ino, _prev_stat.st_mtime_ns, _prev_stat.st_size) if _prev_stat else None

    def _output_ready() -> bool:
        """True once the agent's output differs from (or appears after) whatever
        report.json was there before the pass started."""
        try:
            if not out_host.exists():
                return False
            st = out_host.stat()
        except OSError:
            return False
        return ((st.st_ino, st.st_mtime_ns, st.st_size) != _prev_ident
                if _prev_stat is not None else True)

    try:
        container_id = await _ensure_sandbox()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not start the coder56 sandbox: {exc}")
    try:
        addr = await get_container_address(container_id)
        ready = await check_opencode_ready_async(host=addr, port=4096, timeout=30)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenCode not reachable in sandbox: {exc}")
    if not (ready and ready.get("ready")):
        raise HTTPException(status_code=502, detail=f"OpenCode not ready in sandbox after 30s: {ready}")

    prompt = (
        "You are coder56_reporter — the senior penetration-test report writer. Author the client-ready "
        "report per your system instructions and write ONE JSON file to the OUTPUT PATH.\n\n"
        f"INPUT FILE: {in_container}\n"
        f"OUTPUT PATH: {out_container}\n\n"
        f"There are {len(findings)} finding(s). Read the input; optionally read a finding's evidence_file "
        "for richer context; then write the output JSON atomically and stop. The backend detects completion "
        "by the output file appearing. Preserve each finding's severity/cvss/owasp_id/affected_asset/verified "
        "verbatim and rewrite only the prose. Write the executive summary + overall risk specific to THIS "
        "engagement — no boilerplate, no internal/lab voice.\n\n"
        "The input also carries `coverage_ledger` (the attack-surface items actually tested, by surface "
        "element not OWASP category) and each finding carries `preconditions` + an `attack_path` list. Render "
        "a COVERAGE MATRIX from coverage_ledger grouped by the threat-model crown jewels, frame connected "
        "findings as attack paths (fill each finding's attack_path from the ledger where they chain), and "
        "treat could_not_test/unverifiable surface items as visible coverage gaps — not as clean."
    )
    create = await create_session_async(host=addr, port=4096, title=f"reportwriter-{engagement_id}")
    if not create.get("success") or not create.get("session_id"):
        raise HTTPException(status_code=502,
                            detail=f"Could not create a report-writer session: {create.get('error')}")
    session_id = create["session_id"]
    send = await send_prompt_async(session_id, prompt, host=addr, port=4096,
                                   agent=REPORTWRITER_AGENT_NAME, async_mode=True)
    if not send.get("success"):
        try:
            await abort_session_async(session_id=session_id, host=addr, port=4096)
        except Exception:
            pass
        raise HTTPException(status_code=502, detail=(
            f"Could not send the report-writer prompt — agent '{REPORTWRITER_AGENT_NAME}' may not be baked "
            f"into the image (rebuild ubuntu-24.04-opencode:0.1 + POST /sandbox/restart): {send.get('error')}"))

    deadline = time.monotonic() + REPORTWRITER_TIMEOUT_S
    session_err: Optional[str] = None
    appeared = False
    while time.monotonic() < deadline:
        await asyncio.sleep(5)
        if _output_ready():
            appeared = True
            break
        try:
            res = await get_session_messages_async(session_id=session_id, host=addr, port=4096)
            err = str(res.get("error") or "")
            if res.get("error") and ("not found" in err.lower() or "no such session" in err.lower()):
                session_err = err
                break
        except Exception:
            pass
    if not appeared:
        try:
            await abort_session_async(session_id=session_id, host=addr, port=4096)
        except Exception:
            pass
        if session_err:
            raise HTTPException(status_code=502,
                                detail=f"Report-writer session disappeared ({session_err}).")
        raise HTTPException(status_code=502, detail=(
            f"Report-writer agent did not finish within {REPORTWRITER_TIMEOUT_S}s (session {session_id}). "
            "Retry, or reduce the finding set."))

    try:
        result = json.loads(out_host.read_text(encoding="utf-8", errors="ignore"))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Report-writer output was not valid JSON: {exc}.")
    if not isinstance(result, dict):
        raise HTTPException(status_code=502, detail="Report-writer output was not a JSON object.")
    if "error" in result:
        raise HTTPException(status_code=502, detail=f"Report-writer reported an error: {result.get('error')}")
    if not isinstance(result.get("findings"), list) or not result.get("executive_summary"):
        raise HTTPException(status_code=502,
                            detail="Report-writer output missing required fields (executive_summary/findings).")
    return result


# ---------------------------------------------------------------------------
# MANDATORY + IDEMPOTENT reportwriter reconcile (REC #17).
# Background: _write_reportwriter_input writes <id>.reportwriter_input.json but
# nothing guarantees the reportwriter pass (_run_reportwriter_agent ->
# <id>.report.json + <id>.report.html) ever completes. The pass only ran on an
# explicit operator POST .../report/write; if that was never called, or the
# coder56_reporter sandbox/opencode was unavailable, the engagement was left with
# reportwriter_input.json and NO report (confirmed: 8ef1a41d2388 status=planning
# 7 findings, 0fa53642625e status=active 6 findings, both reportwriter_input.json
# present but no report.json/report.html). This closes that gap and advances the
# engagement status out of 'planning' when findings are present.
# ---------------------------------------------------------------------------

def _engagement_status_after_findings(eng: Dict[str, Any]) -> Optional[str]:
    """Advance engagement.status out of PLANNING/ACTIVE toward REPORTING once the
    engagement has persisted findings. Never forces CLOSED (operator-delivered).
    Returns the new status string, or None if no change is warranted."""
    from ..models import EngagementStatus
    findings = eng.get("findings") or []
    cur = (eng.get("status") or EngagementStatus.PLANNING.value)
    if not findings:
        return None
    if cur in (EngagementStatus.PLANNING.value, EngagementStatus.ACTIVE.value):
        return EngagementStatus.REPORTING.value
    return None


def _deterministic_report_fallback(engagement_id: str, eng: Dict[str, Any],
                                   findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Produce a structured <id>.report.json + <id>.report.html deterministically
    (no agent) so the reconcile gap is ALWAYS closed even when the reportwriter
    sandbox/opencode is unavailable. The HTML reuses the existing render_report
    fallback (the same one GET report.html serves when no cache exists). Returns
    the structured report dict. Idempotent: identical findings -> identical files."""
    detail = _engagement_detail(eng)
    runs = detail["runs"]
    verdicts_by_run = {rid: _read_verdicts_raw(rid, 200) for rid in (eng.get("run_ids") or [])}
    report = {
        "engagement_name": eng.get("name", ""),
        "executive_summary": (
            f"Automated draft of {len(findings)} finding(s) for "
            f"{eng.get('name', 'this engagement')} ("
            f"{sum(1 for f in findings if f.get('verified'))} verifier-confirmed). "
            "Authored by the deterministic fallback because the report-writer agent "
            "was unavailable during the mandatory reconcile pass; re-run POST "
"/engagements/{id}/report/write to regenerate the agent-authored narrative."
        ),
        "overall_risk": "See per-finding severities.",
        "findings": findings,
        "generated_by": "deterministic-fallback",
    }
    out_dir = OUTPUTS_DIR / "engagements"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{engagement_id}.report.json"
    html_path = out_dir / f"{engagement_id}.report.html"
    html = render_report(eng, runs, findings, mitre_catalog(), verdicts_by_run)
    tmp = json_path.with_suffix(json_path.suffix + ".tmp")
    tmp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, json_path)
    try:
        html_path.write_text(html, encoding="utf-8")
    except Exception:
        pass
    return report


async def _reconcile_reportwriter(engagement_id: str, *, force: bool = False) -> bool:
    """Mandatory + idempotent reportwriter pass for ONE engagement.

    Runs the reportwriter agent when <id>.report.json is missing OR older than
    <id>.reportwriter_input.json (stale), and falls back to the deterministic
    renderer if the agent/sandbox is unavailable so a report ALWAYS exists once
    findings are present. Also advances engagement.status from planning/active to
    reporting when findings exist. Best-effort + never raises (called from the
    lead-driver exit and startup sweep). Returns True if (re)generated."""
    if not engagement_id:
        return False
    try:
        eng = _read_engagement(engagement_id)
        if not eng:
            return False
        out_dir = OUTPUTS_DIR / "engagements"
        input_path = out_dir / f"{engagement_id}.reportwriter_input.json"
        json_path = out_dir / f"{engagement_id}.report.json"
        html_path = out_dir / f"{engagement_id}.report.html"

        # 8c2f1a postmortem defect 2: harvest LATE verifier verdicts BEFORE the
        # findings gate below, so a ghost verifier's CONFIRMED finding (written
        # hours after the lead-driver exit) reaches the ledger and this pass
        # regenerates the report instead of finding "no findings" and skipping.
        # Idempotent: the merge skips existing dedup keys, so a re-run of this
        # reconcile adds nothing and the staleness gate stays closed. The
        # engagement lock mirrors the lead-driver exit hook's read-merge-write.
        try:
            async with _engagement_lock(engagement_id):
                harvested = _harvest_late_verdicts(engagement_id, eng)
            if harvested:
                eng = _read_engagement(engagement_id) or eng
        except Exception as exc:
            logger.warning("reconcile_reportwriter[%s] harvest failed: %s",
                           engagement_id, exc)

        # Gather findings: saved first, else draft in-process from run artifacts
        # (so the report is never empty when runs produced CONFIRMED verdicts).
        findings = eng.get("findings") or []
        if not findings:
            live = [r for r in (eng.get("run_ids") or []) if _read_run_meta(r)]
            findings = _coerce_reporter_findings(_draft_findings_inprocess(eng, live)) if live else []
            # Serialization-loss alarm (2026-08-25 audit Rec 1): a run whose
            # verifier files carry content but no parseable VERDICT record may
            # have lost a verdict — log it so the silent-loss class is at least
            # visible in the dashboard log during automatic reconciliation.
            for r in live:
                for alert in _verifier_parse_alerts(r):
                    logger.warning("verifier_parse_alert[%s] %s", r, alert)
        if not findings:
            # Nothing to report yet; nothing to reconcile. Do not touch status.
            return False

        # Idempotency gate: skip if the JSON report exists and is at least as new
        # as the input (unless force=True).
        needs_run = force or (not json_path.exists())
        if not needs_run and input_path.exists():
            try:
                if json_path.stat().st_mtime >= input_path.stat().st_mtime:
                    regenerated = False
                else:
                    needs_run = True
            except OSError:
                needs_run = True
        if not needs_run:
            regenerated = False
            # The agent JSON is fresh — but the cached report.html may have been
            # rendered by an OLDER renderer (schema fixes, e.g. the
            # description/impact/evidence/recommendation finding-body mapping and
            # the nested crown-jewel coverage shape landed 2026-08-17). Re-render
            # from the existing agent JSON whenever report.html is older than
            # report.json; no agent call, cheap and idempotent.
            try:
                if json_path.exists() and (
                        not html_path.exists()
                        or html_path.stat().st_mtime < json_path.stat().st_mtime):
                    report = json.loads(json_path.read_text(encoding="utf-8"))
                    detail = _engagement_detail(eng)
                    verdicts_by_run = {rid: _read_verdicts_raw(rid, 200)
                                       for rid in (eng.get("run_ids") or [])}
                    html = render_client_report(eng, report, detail["runs"],
                                                mitre_catalog(), verdicts_by_run)
                    html_path.write_text(html, encoding="utf-8")
            except Exception as exc:
                logger.warning("reconcile_reportwriter[%s] re-render failed: %s",
                               engagement_id, exc)
        else:
            # Always (re)write the agent input from the CURRENT findings so the
            # input is never stale relative to a saved-finding edit.
            _write_reportwriter_input(engagement_id, eng, findings)
            regenerated = False
            try:
                report = await _run_reportwriter_agent(engagement_id, eng, findings)
                detail = _engagement_detail(eng)
                runs = detail["runs"]
                verdicts_by_run = {rid: _read_verdicts_raw(rid, 200)
                                   for rid in (eng.get("run_ids") or [])}
                html = render_client_report(eng, report, runs, mitre_catalog(), verdicts_by_run)
                try:
                    html_path.write_text(html, encoding="utf-8")
                except Exception:
                    pass
                regenerated = True
            except HTTPException as exc:
                # Agent/sandbox unavailable -> deterministic fallback so the report
                # gap is ALWAYS closed (the original silent-skip failure mode).
                logger.warning("reconcile_reportwriter[%s]: agent failed (%s); "
                               "using deterministic fallback", engagement_id,
                               str(exc.detail)[:160])
                _deterministic_report_fallback(engagement_id, eng, findings)
                regenerated = True
            except Exception as exc:
                logger.warning("reconcile_reportwriter[%s]: agent error (%s); "
                               "using deterministic fallback", engagement_id, exc)
                _deterministic_report_fallback(engagement_id, eng, findings)
                regenerated = True

        # Advance status out of planning/active when findings are present.
        new_status = _engagement_status_after_findings(eng)
        if new_status and (eng.get("status") or "") != new_status:
            eng = _read_engagement(engagement_id) or eng
            eng["status"] = new_status
            eng["updated_at"] = _now_iso()
            _write_engagement(engagement_id, eng)
        return regenerated
    except Exception as exc:
        logger.warning("reconcile_reportwriter[%s] error (continuing): %s",
                       engagement_id, exc)
        return False


async def _reconcile_all_engagement_reports() -> None:
    """Startup sweep: close the reportwriter gap for every existing engagement so
    a backend restart repairs engagements left with reportwriter_input.json but
    no report (8ef1a41d2388, 0fa53642625e). Sequential + best-effort."""
    for eng in _load_all_engagements():
        eid = eng.get("id")
        if not eid:
            continue
        await _reconcile_reportwriter(eid)


@router.post("/engagements/{engagement_id}/report/write", response_class=HTMLResponse)
async def write_engagement_report(engagement_id: str) -> HTMLResponse:
    """Generate the client-ready report: the coder56_reporter report-writer agent
    authors the narrative from the engagement's findings (+ verifier evidence),
    the backend renders it to print-ready HTML and caches it. GET report.html then
    serves the cached version. Uses saved findings if any, else drafts in-process."""
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    saved = eng.get("findings") or []
    if saved:
        findings = saved
    else:
        live = [r for r in (eng.get("run_ids") or []) if _read_run_meta(r)]
        findings = _coerce_reporter_findings(_draft_findings_inprocess(eng, live)) if live else []
    if not findings:
        raise HTTPException(status_code=409,
                            detail="No findings to report. Draft/save findings first, or run the engagement.")
    report = await _run_reportwriter_agent(engagement_id, eng, findings)
    detail = _engagement_detail(eng)
    runs = detail["runs"]
    verdicts_by_run = {rid: _read_verdicts_raw(rid, 200) for rid in (eng.get("run_ids") or [])}
    html = render_client_report(eng, report, runs, mitre_catalog(), verdicts_by_run)
    cache = OUTPUTS_DIR / "engagements" / f"{engagement_id}.report.html"
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(html, encoding="utf-8")
    except Exception:
        pass  # serving the response does not require the cache to persist
    return HTMLResponse(html)


@router.get("/engagements/{engagement_id}/report.html", response_class=HTMLResponse)
async def engagement_report(engagement_id: str) -> HTMLResponse:
    """Serve the client-ready report: the agent-authored version if it has been
    generated (POST .../report/write) and cached, else the deterministic fallback.
    Self-contained, print-ready; the user prints / saves as PDF via the toolbar.

    8c2f1a postmortem defects 2 + 4: before serving a cached report this runs an
    idempotent late-verdict harvest (a ghost verifier can append CONFIRMED
    verdicts hours after the lead-driver exit — they were never picked up) and
    treats a cache older than the engagement's updated_at as stale. Both are
    cheap (jsonl reads + a stat) and this endpoint is called rarely, so they do
    not sit in any hot path."""
    _valid_token(engagement_id, "engagement_id")
    eng = _read_engagement(engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")
    # Defect 2: re-harvest late verifier verdicts into the ledger. When new
    # findings land, re-read the engagement so the regenerated report includes
    # them (and invalidate the cache below so it cannot be served stale). The
    # engagement lock mirrors the lead-driver exit hook's read-merge-write.
    try:
        async with _engagement_lock(engagement_id):
            harvested = _harvest_late_verdicts(engagement_id, eng)
        if harvested:
            eng = _read_engagement(engagement_id) or eng
            _invalidate_report_cache(engagement_id)
    except Exception as exc:
        logger.warning("report_html[%s] late-verdict harvest failed: %s", engagement_id, exc)
    cached, _report_json = _report_cache_paths(engagement_id)
    # Defect 4b: a cache older than the engagement's FINDINGS is stale —
    # regenerate. The newest finding timestamp (not engagement.updated_at) is the
    # signal: updated_at also moves on metadata-only writes (a status advance
    # that follows report generation), which would wrongly discard a fresh
    # agent-authored report. Finding-create/update/delete additionally unlink the
    # cache outright (see the findings handlers).
    if cached.exists():
        try:
            finding_ts = max(
                (_parse_iso_ts(str(f.get("updated_at") or f.get("created_at") or "")) or 0)
                for f in (eng.get("findings") or [])
            ) if (eng.get("findings") or []) else 0
            if finding_ts and cached.stat().st_mtime < finding_ts:
                _invalidate_report_cache(engagement_id)
                cached, _report_json = _report_cache_paths(engagement_id)
        except (OSError, ValueError):
            pass
    if cached.exists():
        return HTMLResponse(cached.read_text(encoding="utf-8", errors="ignore"))
    detail = _engagement_detail(eng)
    runs = detail["runs"]
    verdicts_by_run = {rid: _read_verdicts_raw(rid, 200) for rid in (eng.get("run_ids") or [])}
    return HTMLResponse(render_report(eng, runs, detail["findings"], mitre_catalog(), verdicts_by_run))


# =============================================================================
# Catalog + runs discovery
# =============================================================================

@router.get("/mitre/catalog")
async def get_mitre_catalog() -> Dict[str, Any]:
    return mitre_catalog()


@router.get("/owasp/catalog")
async def get_owasp_catalog() -> Dict[str, Any]:
    """OWASP Top 10 (2021) category catalog for the goal-builder / OWASP plan
    drafting. Mirrors /mitre/catalog."""
    return owasp_catalog()


@router.get("/api-security/catalog")
async def get_api_security_catalog() -> Dict[str, Any]:
    """OWASP API Security Top-10 (2023) category catalog (API1-API10) for the
    goal-builder / API engagement-plan drafting. Mirrors /owasp/catalog and
    /mitre/catalog."""
    return api_security_catalog()


@router.get("/hosts/busy")
async def get_host_busy(topology_id: str = Query(default=""),
                        host_id: str = Query(default="")) -> Dict[str, Any]:
    """Container-busy state for the operator UI.

    With both params: returns the busy state of one host (busy/reason/run_id/
    since/last_verdict_ts) — drive a 'host busy' badge / launch-disable in the
    console.  Without params: returns every currently-registered active host run
    (the in-process registry; not a full historical scan)."""
    if topology_id or host_id:
        return {"topology_id": topology_id, "host_id": host_id,
                **_host_busy_state(topology_id, host_id)}
    active = [
        {"topology_id": k[0], "host_id": k[1], **v}
        for k, v in _active_host_runs.items()
    ]
    return {"active": active, "count": len(active)}


@router.get("/runs")
async def list_runs() -> Dict[str, Any]:
    """Recent real runs under /outputs.

    A directory is a run only when it has a guardrail/run.json manifest. This
    excludes support stores such as .session-runs, engagements, verifier, and
    memory from appearing as phantom executions.
    """
    out: List[Dict[str, Any]] = []
    if OUTPUTS_DIR.exists():
        for child in OUTPUTS_DIR.iterdir():
            if not child.is_dir():
                continue
            gr = child / "guardrail"
            meta_path = gr / "run.json"
            if not meta_path.exists():
                continue
            try:
                mtime = gr.stat().st_mtime
            except OSError:
                mtime = 0
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            out.append({
                "run_id": child.name,
                "has_guardrail": True,
                "mtime": mtime,
                "engagement_id": meta.get("engagement_id"),
                "status": _run_overall_status(meta),
            })
    out.sort(key=lambda r: r.get("mtime", 0), reverse=True)
    return {"runs": out[:50]}
