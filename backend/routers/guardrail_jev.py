"""Inline Jev System One guardrail (OpenRouter) — HTTP surface.

POST /api/guardrail/jev/evaluate   classify a prompt / reasoning trace and
                                   route: block | review | allow
GET  /api/guardrail/jev/config     effective configuration (no secrets)

Orchestration-level guardrail for execution graphs: unstructured payload in,
strictly typed probabilistic decision + routed action out. Fail-safe on any
Jev unavailability is review/escalate — never a silent allow. See
services/guardrail_jev.py for the policy and the OpenRouter call.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from ..services.guardrail_jev import (
    JevGuardrailError,
    evaluate_payload,
    get_effective_config,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/guardrail/jev", tags=["guardrail-jev"])


class JevEvaluateRequest(BaseModel):
    """One payload to classify. payload_text / prompt / trace are aliases —
    the first non-empty one wins (traces and prompts flow through the same
    stateless Jev call)."""

    payload_text: Optional[str] = Field(default=None, min_length=1, max_length=200_000)
    prompt: Optional[str] = Field(default=None, min_length=1, max_length=200_000)
    trace: Optional[str] = Field(default=None, min_length=1, max_length=200_000)
    source: Optional[str] = Field(default=None, max_length=200)
    run_id: Optional[str] = Field(default=None, max_length=200)
    agent_id: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="before")
    @classmethod
    def _require_payload(cls, data):
        if isinstance(data, dict):
            if not any(str(data.get(k) or "").strip()
                       for k in ("payload_text", "prompt", "trace")):
                raise ValueError("one of payload_text / prompt / trace is required")
        return data

    def payload(self) -> str:
        for k in ("payload_text", "prompt", "trace"):
            val = getattr(self, k)
            if val and val.strip():
                return val
        raise ValueError("no payload")  # unreachable: validator rejects empties


@router.post("/evaluate")
async def evaluate(req: JevEvaluateRequest) -> JSONResponse:
    try:
        result = await evaluate_payload(
            req.payload(),
            source=req.source, run_id=req.run_id, agent_id=req.agent_id)
        return JSONResponse(result, status_code=200)
    except JevGuardrailError as exc:
        # Fail-safe: route to human review, never allow through on error.
        logger.warning("Jev guardrail evaluate failed (%d): %s", exc.status_code, exc.reason)
        return JSONResponse(
            {
                "decision": None,
                "action": "review",
                "platform_decision": "escalate",
                "reason": f"fail-safe: {exc.reason}",
                "error": exc.reason,
            },
            status_code=exc.status_code,
        )


@router.get("/config")
async def read_config() -> dict:
    """Effective Jev configuration — keyless and secret-free."""
    return get_effective_config()
