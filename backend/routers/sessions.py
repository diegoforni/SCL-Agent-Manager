"""
Sessions Router for Agent Manager

Provides REST and WebSocket endpoints for managing Agent sessions:
- GET /api/sessions/list - List all sessions
- POST /api/sessions - Create a new session
- GET /api/sessions/{session_id}/messages - Get session messages
- POST /api/sessions/{session_id}/prompt - Send a prompt to a session
- WebSocket /api/sessions/ws/{session_id} - Real-time streaming
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import json
import re
import asyncio
import logging

from ..models import (
    SessionCreateRequest, 
    SessionInfo, 
    SessionMessage, 
    SessionState,
    SessionMetrics,
    SessionPromptRequest
)
from ..services.container_addr import get_container_address, ContainerAddressError
from ..services.opencode_client import create_session_async, send_prompt_async, get_session_messages_async, list_session_objects_async, _ensure_network_connectivity
from ..services.session_capture import resolve_run_id, capture_session_messages, OUTPUTS_DIR
from ..services.state_manager import get_state_manager

router = APIRouter(prefix="/api/sessions", tags=["sessions"])
logger = logging.getLogger(__name__)

# Active websocket connections
_active_connections: Dict[str, List[WebSocket]] = {}

class PromptResponse(BaseModel):
    message_id: str
    response: str
    session_id: str
    timestamp: datetime

async def _get_container_address(container_id: str) -> str:
    """Helper to get the resolvable address of a container (shared with the defender)."""
    try:
        return await get_container_address(container_id)
    except ContainerAddressError as e:
        msg = str(e)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg)
        raise HTTPException(status_code=500, detail=msg)

async def _capture_turn(container_id: str, agent_type: str, session_id: str, host_addr: str) -> None:
    """Best-effort: after a prompt turn, fetch the session's messages from the
    OpenCode server and persist them to OUTPUTS_DIR/<run_id>/<agent>/opencode_api_messages.json
    so dashboard-driven runs produce the same per-agent artifacts (and Replay-readable
    state) as the standalone experiment runners. Never raises."""
    try:
        msgs_result = await get_session_messages_async(session_id=session_id, host=host_addr, port=4096)
        messages = msgs_result.get("messages", []) if msgs_result.get("success") else []
        run_id = await resolve_run_id(container_id)
        capture_session_messages(run_id, agent_type, session_id, messages)
    except Exception as exc:
        logger.debug("session capture skipped for %s: %s", session_id[:12], exc)

async def _forward_goal_to_guardrail(container_id: str, agent_type: str, goal_text: str) -> None:
    """Append the operator's prompt to the coder56 guardrail's live goal file
    AND set the run's guardrail mode to "auto".

    The ClawKeeper guardrail (scope mode) reads /outputs/<run_id>/guardrail/goal.txt on
    every command and keeps the red-teamer in scope of it. We accumulate every
    coder56 session prompt so the goal is the full directive history (later
    directives refine/extend earlier ones). Best-effort: never raises into the
    prompt path. Only coder56 — soc_god keeps its baked-in GUARDRAIL_GOAL.

    mode.txt=auto: agent-manager sessions are the AUTONOMOUS surface — the
    judge still gates every command, but its verdict is enforced with no human
    (execute/sanitize run; refuse returns feedback). Without this the run
    defaults to "medium" and the first judge-flagged command parks the agent
    in awaitHumanApproval forever — the Agents page has no approvals queue, so
    the session just looks stuck (observed: one stale undecided approval from
    a dead session blocked a NEW session for hours via awaitRunClearOfPending,
    which polls before every command). HITL stays on the coder56 console,
    whose launch writes its own mode.txt per criticality.
    """
    if agent_type != "coder56" or not (goal_text and goal_text.strip()):
        return
    try:
        run_id = await resolve_run_id(container_id)
        goal_dir = OUTPUTS_DIR / run_id / "guardrail"
        goal_dir.mkdir(parents=True, exist_ok=True)
        # OS append is write-race-free; '--- directive ---' delimits cumulative goals.
        with open(goal_dir / "goal.txt", "a") as f:
            f.write(f"\n--- directive ---\n{goal_text.strip()}\n")
        (goal_dir / "mode.txt").write_text("auto", encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not forward guardrail goal for %s: %s", container_id[:12], exc)

def _transform_opencode_message(opencode_msg: Dict[str, Any]) -> SessionMessage:
    """Transform OpenCode message format to SessionMessage format.

    OpenCode format:
    {
        "info": {
            "id": "...",
            "role": "user|assistant|system|tool",
            "time": {"created": timestamp, "completed": timestamp},
            ...
        },
        "parts": [
            {"type": "text", "text": "..."},
            {"type": "tool", "tool": "bash", "state": {...}}
        ]
    }

    SessionMessage format:
    {
        "id": "...",
        "role": "...",
        "timestamp": "...",
        "content": "...",
        "tool_calls": [...],
        "tokens_used": 0
    }
    """
    info = opencode_msg.get("info", {})
    parts = opencode_msg.get("parts", [])

    # Extract basic fields
    msg_id = info.get("id", str(uuid.uuid4()))
    role = info.get("role", "assistant")
    if role not in ["user", "assistant", "system", "tool"]:
        role = "assistant"

    # Extract timestamp
    time_info = info.get("time", {})
    timestamp_ms = time_info.get("created") or time_info.get("updated")
    if timestamp_ms:
        timestamp = datetime.fromtimestamp(timestamp_ms / 1000)
    else:
        timestamp = datetime.utcnow()

    # Extract content from parts
    content_parts = []
    tool_calls = []

    for part in parts:
        part_type = part.get("type", "")

        if part_type == "text":
            text = part.get("text", "")
            content_parts.append(text)

        elif part_type == "tool":
            tool_name = part.get("tool", "unknown")
            state = part.get("state", {})

            tool_call = {
                "id": str(uuid.uuid4()),
                "type": "function",
                "function": {
                    "name": tool_name,
                    "arguments": json.dumps(state.get("input", {}), default=str)
                }
            }

            # Add output if available
            if state.get("output"):
                tool_call["result"] = state.get("output")

            tool_calls.append(tool_call)

    content = "\n".join(content_parts)

    # Extract token info if available
    tokens = info.get("tokens", {})
    tokens_used = tokens.get("total", 0)

    return SessionMessage(
        id=msg_id,
        timestamp=timestamp,
        role=role,
        content=content,
        tool_calls=tool_calls,
        tokens_used=tokens_used
    )

@router.get("/list", response_model=List[SessionInfo])
async def list_sessions(
    limit: int = 100,
    offset: int = 0,
    status_filter: Optional[str] = None
) -> List[SessionInfo]:
    """List all sessions with optional filtering."""
    sm = get_state_manager()
    sessions = sm.get_all_sessions()
    
    # Convert state dicts to SessionInfo models
    session_list = []
    for sid, s_data in sessions.items():
        if status_filter and s_data.get("state") != status_filter:
            continue
            
        session_list.append(SessionInfo(
            session_id=s_data.get("session_id", sid),
            container_id=s_data.get("container_id", ""),
            host_id=s_data.get("host_id", ""),
            agent_type=s_data.get("agent_type", "coder56"),
            state=SessionState(s_data.get("state", "created")),
            messages=[], # Messages aren't typically returned in list view
            metrics=SessionMetrics(**s_data.get("metrics", {})),
            created_at=datetime.fromisoformat(s_data.get("created_at")) if s_data.get("created_at") else datetime.utcnow()
        ))
        
    session_list.sort(key=lambda x: x.created_at, reverse=True)
    return session_list[offset:offset + limit]

@router.post("", response_model=SessionInfo)
async def create_session(request: SessionCreateRequest) -> SessionInfo:
    """Create a new session on the specified container."""

    # Ensure network connectivity to the container
    await _ensure_network_connectivity(request.container_id)

    host_addr = await _get_container_address(request.container_id)

    # Hit the OpenCode server to create session (without agent - agent is specified per-message)
    result = await create_session_async(
        host=host_addr,
        port=4096,
        title=request.initial_prompt[:50] if request.initial_prompt else "New Session"
    )

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=f"Failed to create OpenCode session: {result.get('error')}")

    session_id = result.get("session_id")

    sm = get_state_manager()
    session_data = {
        "container_id": request.container_id,
        "host_id": request.host_id,
        "agent_type": request.agent_type.value,
        "state": SessionState.CREATED.value,
        "metrics": {"total_messages": 0, "total_tokens_used": 0, "execution_time_seconds": 0.0, "tool_calls_count": 0}
    }

    sm.create_session(session_id, session_data)

    # If initial prompt is provided, send it synchronously to ensure agent processes it
    # Agent is specified here (in the prompt), not during session creation
    if request.initial_prompt:
        try:
            # Arm the coder56 guardrail with the operator's goal before the agent's
            # first commands run.
            await _forward_goal_to_guardrail(request.container_id, request.agent_type.value, request.initial_prompt)
            result = await send_prompt_async(
                session_id=session_id,
                prompt=request.initial_prompt,
                host=host_addr,
                port=4096,
                agent=request.agent_type.value,
                async_mode=False,  # Use sync mode to ensure prompt is processed
                timeout=120  # Allow 2 minutes for agent to complete
            )
            if not result.get("success"):
                logger.warning(f"Initial prompt failed to send: {result.get('error')}")
                # Continue anyway - session is created, prompt can be resent later
            else:
                logger.info(f"Initial prompt sent successfully to session {session_id[:12]}")
            # Always persist whatever messages the session has so far (best-effort),
            # even if the prompt timed out or failed — autonomous agents (e.g. soc_god)
            # routinely exceed the 120s sync timeout, and we still want the per-agent
            # opencode_api_messages.json written under the run id.
            await _capture_turn(request.container_id, request.agent_type.value, session_id, host_addr)
            sm.update_session(session_id, {"state": SessionState.RUNNING.value})
        except Exception as e:
            logger.error(f"Error sending initial prompt: {e}")
            # Best-effort capture even on exception (e.g. timeout) so a long-running
            # autonomous agent still gets its accumulated messages persisted.
            await _capture_turn(request.container_id, request.agent_type.value, session_id, host_addr)
            # Continue anyway - session is created, prompt can be resent later
            sm.update_session(session_id, {"state": SessionState.RUNNING.value})

    return SessionInfo(
        session_id=session_id,
        container_id=request.container_id,
        host_id=request.host_id,
        agent_type=request.agent_type,
        state=SessionState.CREATED if not request.initial_prompt else SessionState.RUNNING,
        messages=[],
        metrics=SessionMetrics()
    )

@router.get("/{session_id}", response_model=SessionInfo)
async def get_session(session_id: str) -> SessionInfo:
    """Get information about a specific session."""
    sm = get_state_manager()
    s_data = sm.get_session(session_id)
    if not s_data:
        raise HTTPException(status_code=404, detail="Session not found")
        
    return SessionInfo(
        session_id=s_data.get("session_id", session_id),
        container_id=s_data.get("container_id", ""),
        host_id=s_data.get("host_id", ""),
        agent_type=s_data.get("agent_type", "coder56"),
        state=SessionState(s_data.get("state", "created")),
        messages=[],
        metrics=SessionMetrics(**s_data.get("metrics", {})),
        created_at=datetime.fromisoformat(s_data.get("created_at")) if s_data.get("created_at") else datetime.utcnow()
    )

@router.get("/{session_id}/messages", response_model=List[SessionMessage])
async def get_messages(
    session_id: str,
    limit: int = 100,
    offset: int = 0
) -> List[SessionMessage]:
    """Get messages for a specific session from OpenCode."""
    sm = get_state_manager()
    session = sm.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # The manager is attached to topology networks dynamically. A manager
    # container rebuild drops those out-of-band attachments, so restore the
    # target network before resolving/fetching a persisted session.
    await _ensure_network_connectivity(session.get("container_id"))

    host_addr = await _get_container_address(session.get("container_id"))

    result = await get_session_messages_async(
        session_id=session_id,
        host=host_addr,
        port=4096
    )

    if not result.get("success"):
        # Not found could mean it hasn't started generating, just return empty
        if "not found" in str(result.get("error", "")).lower():
            return []
        raise HTTPException(status_code=500, detail=f"Failed to get messages: {result.get('error')}")

    messages = result.get("messages", [])

    # Transform OpenCode messages to SessionMessage format
    output = [_transform_opencode_message(m) for m in messages]

    return output[offset:offset+limit]

# --- Sub-agent discovery (coder56 native_subagents orchestration) -------------
#
# A coder56 engagement runs as ONE opencode session (coder56_lead) that spawns
# coder56_phase / coder56_verifier subagents via the Task tool. Those children
# are full opencode sessions (parentID points at the spawner) but are NOT
# registered in the state manager, so the Agents page historically showed only
# the Lead's stream. The two endpoints below expose the whole tree.

_SUBAGENT_TITLE_RE = re.compile(r"coder56_(\w+)")

def _label_subagent(session_obj: Dict[str, Any], depth: int) -> str:
    """Best-effort agent label for a child opencode session. The session object
    does not carry the agent name, so fall back to depth-based defaults that
    match the coder56 orchestration (depth 1 = phase, depth 2 = verifier)."""
    title = str(session_obj.get("title") or "")
    m = _SUBAGENT_TITLE_RE.search(title)
    if m:
        return f"coder56_{m.group(1)}"
    if depth == 1:
        return "coder56_phase"
    if depth == 2:
        return "coder56_verifier"
    return f"subagent"

async def _resolve_session_tree(session_id: str) -> Dict[str, Any]:
    """Shared lookup for the agents endpoints: root state-manager session plus
    its opencode session objects. Raises HTTPException on missing pieces."""
    sm = get_state_manager()
    session = sm.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    await _ensure_network_connectivity(session.get("container_id"))
    host_addr = await _get_container_address(session.get("container_id"))

    sres = await list_session_objects_async(host=host_addr, port=4096)
    if not sres.get("success"):
        # Container/opencode down (topology stopped, sandbox rebuilding) — return
        # an empty tree rather than a 500 so the UI can fall back to the Lead.
        return {"session": session, "host_addr": host_addr, "objects": {}}

    objects = {
        s.get("id"): s
        for s in (sres.get("sessions") or [])
        if isinstance(s, dict) and s.get("id")
    }
    return {"session": session, "host_addr": host_addr, "objects": objects}

@router.get("/{session_id}/agents")
async def list_session_agents(session_id: str) -> Dict[str, Any]:
    """Agent sessions participating in this session's run: the root (lead)
    session, every opencode child session spawned under it via the Task tool
    (transitively), and the container's guardrail judge session(s) if present.
    Children are ordered oldest-first so the UI can render a stable timeline."""
    tree = await _resolve_session_tree(session_id)
    objects: Dict[str, Any] = tree["objects"]

    def _created(obj: Dict[str, Any]) -> float:
        v = ((obj.get("time") or {}).get("created")) or 0
        return v if isinstance(v, (int, float)) else 0

    # BFS from the root over parentID links.
    descendants: Dict[str, int] = {}
    frontier = [session_id]
    depth = 0
    while frontier:
        next_frontier = []
        for node in frontier:
            for sid, obj in objects.items():
                if obj.get("parentID") == node and sid not in descendants:
                    descendants[sid] = depth + 1
                    next_frontier.append(sid)
        frontier = next_frontier
        depth += 1

    def _entry(sid: str, label: str, dep: int, kind: str = "agent") -> Dict[str, Any]:
        obj = objects.get(sid) or {}
        t = obj.get("time") or {}
        return {
            "session_id": sid,
            "label": label,
            "title": str(obj.get("title") or ""),
            "parent_id": obj.get("parentID"),
            "depth": dep,
            "kind": kind,
            "created": t.get("created"),
            "updated": t.get("updated"),
        }

    agents = [_entry(session_id, "coder56_lead", 0)] if session_id in objects else [
        # Root not yet visible via /session (created but never prompted).
        {"session_id": session_id, "label": "coder56_lead", "title": "",
         "parent_id": None, "depth": 0, "kind": "agent",
         "created": None, "updated": None}
    ]
    for sid, dep in sorted(descendants.items(), key=lambda kv: _created(objects.get(kv[0]) or {})):
        agents.append(_entry(sid, _label_subagent(objects.get(sid) or {}, dep), dep))

    # The guardrail judge runs its own (unparented) opencode session titled
    # "guardrail-<agent>" — surface it last when present. The UI hides these
    # behind a toggle by default (kind=guardrail); they update on every
    # adjudicated command and would otherwise dominate the stream.
    has_guardrail_session = False
    for sid, obj in objects.items():
        title = str(obj.get("title") or "")
        if sid in descendants or sid == session_id:
            continue
        if title.lower().startswith("guardrail"):
            has_guardrail_session = True
            agents.append(_entry(sid, title or "guardrail", 1, kind="guardrail"))

    # Current guardrail builds judge via direct LLM calls and leave NO opencode
    # session behind — their only footprint is the run's verdicts.ndjson.
    # Synthesize a pseudo-agent from that file so the toggle still surfaces
    # guardrail activity for these deployments.
    if not has_guardrail_session:
        run_id = ""
        try:
            run_id = await resolve_run_id(tree["session"].get("container_id"))
        except Exception:
            run_id = ""
        vpath = (OUTPUTS_DIR / run_id / "guardrail" / "verdicts.ndjson") if run_id else None
        if vpath and vpath.is_file():
            agents.append({
                "session_id": f"guardrail:{run_id}",
                "label": "guardrail (verdicts)",
                "title": f"guardrail/verdicts.ndjson — {run_id}",
                "parent_id": None,
                "depth": 1,
                "kind": "guardrail",
                "created": None,
                "updated": int(vpath.stat().st_mtime * 1000),
            })

    return {
        "session_id": session_id,
        "container_id": tree["session"].get("container_id"),
        "agents": agents,
    }

def _verdict_messages(run_id: str, limit: int, offset: int) -> List[SessionMessage]:
    """Render the run's guardrail verdicts.ndjson tail as a chronological
    message stream (one SessionMessage per verdict). Page 0 = the most recent
    `limit` verdicts, oldest-first so it reads like a chat."""
    path = OUTPUTS_DIR / run_id / "guardrail" / "verdicts.ndjson"
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    recs: List[Dict[str, Any]] = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            recs.append(json.loads(ln))
        except Exception:
            continue
    end = len(recs) - offset
    start = max(0, end - limit)
    out: List[SessionMessage] = []
    for i, d in enumerate(recs[start:end], start=start):
        ts = str(d.get("ts") or "")
        try:
            timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else datetime.utcnow()
        except ValueError:
            timestamp = datetime.utcnow()
        decision = str(d.get("decision") or "?").upper()
        cmd = " ".join(str(d.get("command") or "").split())[:200]
        reason = " ".join(str(d.get("reason") or "").split())[:300]
        exit_code = d.get("exit_code")
        content = f"[{decision}] {cmd}\n{reason}"
        if exit_code is not None:
            content += f"\nexit={exit_code}"
        out.append(SessionMessage(
            id=f"verdict-{run_id}-{i}",
            timestamp=timestamp,
            role="assistant",
            content=content,
            tool_calls=[],
            tokens_used=0,
        ))
    return out

@router.get("/{session_id}/agents/{agent_session_id}/messages", response_model=List[SessionMessage])
async def get_agent_messages(
    session_id: str,
    agent_session_id: str,
    limit: int = 100,
    offset: int = 0
) -> List[SessionMessage]:
    """Messages for one of the session's agents (root, subagent, or guardrail).
    The agent session id must belong to the root's tree — arbitrary container
    sessions are not addressable through this endpoint. Guardrail pseudo-ids
    ("guardrail:<run_id>") render the run's verdict log instead."""
    if agent_session_id.startswith("guardrail:"):
        return _verdict_messages(agent_session_id.split(":", 1)[1], limit, offset)

    tree = await _resolve_session_tree(session_id)
    objects: Dict[str, Any] = tree["objects"]

    # Transitive closure over parentID (dict order is not guaranteed to be
    # parent-before-child), plus the guardrail judge session(s).
    allowed = {session_id}
    changed = True
    while changed:
        changed = False
        for sid, obj in objects.items():
            if sid in allowed:
                continue
            if obj.get("parentID") in allowed or (
                str(obj.get("title") or "").lower().startswith("guardrail")
            ):
                allowed.add(sid)
                changed = True
    if agent_session_id not in allowed:
        raise HTTPException(status_code=404, detail="Agent session is not part of this session's run")

    result = await get_session_messages_async(
        session_id=agent_session_id,
        host=tree["host_addr"],
        port=4096
    )
    if not result.get("success"):
        if "not found" in str(result.get("error", "")).lower():
            return []
        raise HTTPException(status_code=500, detail=f"Failed to get messages: {result.get('error')}")

    return [_transform_opencode_message(m) for m in result.get("messages", [])][offset:offset + limit]

@router.post("/{session_id}/prompt", response_model=PromptResponse)
async def send_prompt(
    session_id: str,
    request: SessionPromptRequest
) -> PromptResponse:
    """Send a prompt to an existing session."""
    sm = get_state_manager()
    session = sm.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Ensure network connectivity to the container
    await _ensure_network_connectivity(session.get("container_id"))

    host_addr = await _get_container_address(session.get("container_id"))

    # Refresh the coder56 guardrail's live goal with this latest directive (appended
    # to the cumulative goal) before the agent acts on the prompt.
    await _forward_goal_to_guardrail(session.get("container_id"), session.get("agent_type"), request.prompt)

    result = await send_prompt_async(
        session_id=session_id,
        prompt=request.prompt,
        host=host_addr,
        port=4096,
        agent=session.get("agent_type"),
        async_mode=False,
        timeout=request.timeout_seconds or 120
    )
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=f"Failed to send prompt: {result.get('error')}")
        
    # Update state
    sm.update_session(session_id, {"state": SessionState.RUNNING.value, "updated_at": datetime.utcnow().isoformat()})

    # Persist this turn's messages to the per-agent opencode_api_messages.json
    # (best-effort; never blocks the response).
    await _capture_turn(session.get("container_id"), session.get("agent_type"), session_id, host_addr)
    
    resp_data = result.get("response", {})
    return PromptResponse(
        message_id=str(uuid.uuid4()),
        response=resp_data.get("content", "Prompt sent successfully"),
        session_id=session_id,
        timestamp=datetime.utcnow()
    )

@router.delete("/{session_id}")
async def delete_session(session_id: str) -> Dict[str, str]:
    """Delete a session."""
    sm = get_state_manager()
    if sm.get_session(session_id):
        sm.close_session(session_id)
        # Would optionally hit OpenCode /abort or /delete here if supported
    return {"message": f"Session {session_id} deleted"}

@router.websocket("/ws/{session_id}")
async def websocket_session(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for real-time session streaming.
    (This is a simplified passthrough mock for UI compatibility until UI is fully switched to polling or proper WS)
    """
    await websocket.accept()
    
    if session_id not in _active_connections:
        _active_connections[session_id] = []
    _active_connections[session_id].append(websocket)
    
    try:
        await websocket.send_json({
            "type": "connected",
            "data": {"session_id": session_id, "timestamp": datetime.utcnow().isoformat()}
        })
        while True:
            raw = await websocket.receive_text()
            # Just keep connection alive, UI might send ping
            try:
                msg = json.loads(raw)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if session_id in _active_connections:
            if websocket in _active_connections[session_id]:
                _active_connections[session_id].remove(websocket)
            if not _active_connections[session_id]:
                del _active_connections[session_id]
