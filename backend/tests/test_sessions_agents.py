"""Tests for the sub-agent discovery endpoints on the sessions router.

A coder56 native_subagents run is ONE opencode session (coder56_lead) that
spawns coder56_phase / coder56_verifier children via the Task tool. Those child
sessions exist only inside opencode (parentID tree) and were invisible to the
Agents page. GET /api/sessions/{id}/agents and
GET /api/sessions/{id}/agents/{agent_session_id}/messages expose them.

Everything external (state manager, container address, opencode HTTP API) is
monkeypatched — no containers are needed.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.routers import sessions as s


def _obj(sid, parent=None, title="", created=0, updated=0):
    return {
        "id": sid,
        "parentID": parent,
        "title": title,
        "time": {"created": created, "updated": updated},
    }


@pytest.fixture
def patched(monkeypatch):
    """One lead session with a phase child, that phase's verifier child, an
    unrelated session, and a guardrail judge session."""
    objects = [
        _obj("ses_lead", title="engagement directive", created=1, updated=50),
        _obj("ses_phase1", parent="ses_lead", title="OBJECTIVE: Phase 1 recon", created=2, updated=40),
        _obj("ses_verifier1", parent="ses_phase1", title="verify candidate", created=3, updated=30),
        _obj("ses_other_root", title="someone else's session", created=4, updated=60),
        _obj("ses_guard", title="guardrail-coder56", created=5, updated=45),
    ]

    recorded = {}

    class FakeSM:
        def get_session(self, sid):
            if sid != "ses_lead":
                return None
            return {"container_id": "ctr-1", "host_id": "h1", "agent_type": "coder56"}

    async def fake_list(host=None, port=None, timeout=None):
        return {"success": True, "sessions": objects}

    async def fake_messages(session_id=None, host=None, port=None):
        recorded["fetched"] = session_id
        return {
            "success": True,
            "messages": [
                {"info": {"id": "m1", "role": "assistant", "time": {"created": 1}}, "parts": [{"type": "text", "text": "hi"}]}
            ],
        }

    monkeypatch.setattr(s, "get_state_manager", lambda: FakeSM())
    monkeypatch.setattr(s, "_ensure_network_connectivity", lambda cid: _async_none())
    monkeypatch.setattr(s, "_get_container_address", lambda cid: _async_ret("10.0.0.5"))
    monkeypatch.setattr(s, "list_session_objects_async", fake_list)
    monkeypatch.setattr(s, "get_session_messages_async", fake_messages)
    return recorded


def _async_none():
    import asyncio
    return asyncio.sleep(0)


def _async_ret(v):
    async def coro():
        return v
    return coro()


@pytest.mark.anyio
async def test_agents_tree_includes_descendants_and_guardrail(patched):
    from backend.services import opencode_client  # noqa: F401  (import path sanity)

    result = await s.list_session_agents("ses_lead")

    labels = {a["label"]: a["session_id"] for a in result["agents"]}
    assert labels["coder56_lead"] == "ses_lead"
    assert labels["coder56_phase"] == "ses_phase1"
    assert labels["coder56_verifier"] == "ses_verifier1"
    assert labels["guardrail-coder56"] == "ses_guard"
    # Kind discriminator: tree sessions are agents, the judge is guardrail.
    kinds = {a["session_id"]: a["kind"] for a in result["agents"]}
    assert kinds["ses_lead"] == "agent"
    assert kinds["ses_phase1"] == "agent"
    assert kinds["ses_verifier1"] == "agent"
    assert kinds["ses_guard"] == "guardrail"
    # The unrelated root session must NOT be exposed.
    assert "ses_other_root" not in {a["session_id"] for a in result["agents"]}
    # Oldest-first ordering.
    ids = [a["session_id"] for a in result["agents"]]
    assert ids.index("ses_phase1") < ids.index("ses_verifier1")


@pytest.mark.anyio
async def test_agent_messages_allowed_for_tree_members(patched):
    msgs = await s.get_agent_messages("ses_lead", "ses_verifier1")
    assert patched["fetched"] == "ses_verifier1"
    assert msgs and msgs[0].content == "hi"

    # The lead itself is addressable too.
    await s.get_agent_messages("ses_lead", "ses_lead")
    assert patched["fetched"] == "ses_lead"


@pytest.mark.anyio
async def test_agent_messages_rejects_foreign_session(patched):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await s.get_agent_messages("ses_lead", "ses_other_root")
    assert exc.value.status_code == 404


@pytest.mark.anyio
async def test_unknown_root_session_404(patched, monkeypatch):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await s.list_session_agents("ses_nope")
    assert exc.value.status_code == 404


@pytest.fixture
def patched_no_guardrail_session(monkeypatch, tmp_path):
    """Same container as `patched` but WITHOUT the guardrail-titled opencode
    session — the deployment shape where the guardrail judges out-of-band and
    only verdicts.ndjson remains."""
    objects = [
        _obj("ses_lead", title="engagement directive", created=1, updated=50),
        _obj("ses_phase1", parent="ses_lead", title="OBJECTIVE: Phase 1", created=2, updated=40),
    ]

    class FakeSM:
        def get_session(self, sid):
            if sid != "ses_lead":
                return None
            return {"container_id": "ctr-1", "host_id": "h1", "agent_type": "coder56"}

    async def fake_list(host=None, port=None, timeout=None):
        return {"success": True, "sessions": objects}

    async def fake_resolve(container_id):
        return "run-x"

    (tmp_path / "run-x" / "guardrail").mkdir(parents=True)
    (tmp_path / "run-x" / "guardrail" / "verdicts.ndjson").write_text(
        '{"ts": "2026-09-05T03:49:52.957Z", "decision": "execute", "command": "nmap -sV target", '
        '"reason": "in scope", "exit_code": 0}\n'
        '{"ts": "2026-09-05T03:50:48.547Z", "decision": "refuse", "command": "rm -rf /", '
        '"reason": "destructive", "exit_code": null}\n'
        "not-json-garbage\n"
    )

    monkeypatch.setattr(s, "get_state_manager", lambda: FakeSM())
    monkeypatch.setattr(s, "_ensure_network_connectivity", lambda cid: _async_none())
    monkeypatch.setattr(s, "_get_container_address", lambda cid: _async_ret("10.0.0.5"))
    monkeypatch.setattr(s, "list_session_objects_async", fake_list)
    monkeypatch.setattr(s, "resolve_run_id", fake_resolve)
    monkeypatch.setattr(s, "OUTPUTS_DIR", tmp_path)
    return tmp_path


@pytest.mark.anyio
async def test_guardrail_pseudo_agent_from_verdicts(patched_no_guardrail_session):
    """With no guardrail opencode session, the verdict log becomes a
    kind=guardrail pseudo-agent so the UI toggle still works."""
    result = await s.list_session_agents("ses_lead")

    guard = [a for a in result["agents"] if a["kind"] == "guardrail"]
    assert len(guard) == 1
    assert guard[0]["session_id"] == "guardrail:run-x"
    assert guard[0]["label"] == "guardrail (verdicts)"
    assert isinstance(guard[0]["updated"], int)

    msgs = await s.get_agent_messages("ses_lead", "guardrail:run-x")
    assert len(msgs) == 2  # garbage line skipped
    assert msgs[0].content.startswith("[EXECUTE] nmap -sV target")
    assert "[REFUSE] rm -rf /" in msgs[1].content
    assert msgs[0].timestamp <= msgs[1].timestamp


@pytest.mark.anyio
async def test_guardrail_pseudo_agent_absent_without_verdicts(
        patched_no_guardrail_session, monkeypatch):
    """No judge session AND no verdicts file -> no guardrail entry at all."""
    import shutil
    shutil.rmtree(patched_no_guardrail_session / "run-x" / "guardrail")
    result = await s.list_session_agents("ses_lead")
    assert not [a for a in result["agents"] if a["kind"] == "guardrail"]
    assert await s.get_agent_messages("ses_lead", "guardrail:run-x") == []


@pytest.mark.anyio
async def test_goal_forward_sets_auto_mode(monkeypatch, tmp_path):
    """Agent-manager sessions are the autonomous surface: forwarding a goal
    must also write mode.txt=auto so a judge-flagged command is auto-decided
    instead of parking the agent in awaitHumanApproval (the Agents page has no
    approvals queue — HITL belongs to the coder56 console launches)."""
    import backend.routers.sessions as s

    async def fake_resolve(container_id):
        return "run-am"

    monkeypatch.setattr(s, "resolve_run_id", fake_resolve)
    monkeypatch.setattr(s, "OUTPUTS_DIR", tmp_path)

    await s._forward_goal_to_guardrail("ctr-1", "coder56", "enumerate the target subnet")

    goal = (tmp_path / "run-am" / "guardrail" / "goal.txt").read_text()
    assert "enumerate the target subnet" in goal
    mode = (tmp_path / "run-am" / "guardrail" / "mode.txt").read_text().strip().lower()
    assert mode == "auto"

    # Non-coder56 agents keep their baked-in goal and must not touch mode.txt.
    await s._forward_goal_to_guardrail("ctr-1", "soc_god", "watch the database")
    assert not (tmp_path / "run-am" / "guardrail" / "goal.txt").read_text().endswith(
        "watch the database\n")


@pytest.fixture
def anyio_backend():
    return "asyncio"
