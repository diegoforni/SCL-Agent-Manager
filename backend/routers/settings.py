"""
Settings Router for Agent Manager Plugin

Provides endpoints for managing LLM credentials and provider configuration.
Credentials are stored in a .env file and exposed to OpenCode agents via
environment variables when topologies are started.
"""

import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from dotenv import dotenv_values
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])

# ── Configuration ─────────────────────────────────────────────────────

CREDENTIALS_PATH = Path(os.getenv("CREDENTIALS_ENV_PATH", "/app/state/credentials.env"))

# ── Schema ────────────────────────────────────────────────────────────

VARIABLE_SCHEMA: list[dict[str, Any]] = [
    {
        "key": "OPENCODE_API_KEY",
        "label": "API Key",
        "group": "provider",
        "type": "password",
        "required": True,
        "description": "API key for the LLM provider. Used by all OpenCode agents.",
    },
    {
        "key": "LLM_URL",
        "label": "Base URL",
        "group": "provider",
        "type": "text",
        "required": True,
        "placeholder": "https://api.openai.com/v1",
        "description": "Base URL for the LLM provider's chat completions API.",
    },
    {
        "key": "LLM_MODEL",
        "label": "Model",
        "group": "provider",
        "type": "text",
        "required": True,
        "placeholder": "gpt-4o",
        "description": "Model identifier to use for all OpenCode agents.",
    },
    {
        "key": "OPENROUTER_API_KEY",
        "label": "OpenRouter API Key",
        "group": "guardrails",
        "type": "password",
        "required": False,
        "description": "Key for the Jev inline prompt-injection guardrail (openrouter.ai).",
    },
]

GROUPS = [
    {
        "id": "provider",
        "title": "LLM Provider",
        "description": "Configure the LLM provider credentials used by OpenCode agents.",
    },
    {
        "id": "guardrails",
        "title": "Guardrails",
        "description": "Inline Jev prompt-injection classifier (OpenRouter).",
    },
]

PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "openai": {
        "LLM_URL": "https://api.openai.com/v1",
    },
    "anthropic": {
        "LLM_URL": "https://api.anthropic.com/v1",
    },
    "gemini": {
        "LLM_URL": "https://generativelanguage.googleapis.com/v1beta/openai",
    },
    "einfra": {
        "LLM_URL": "https://llm.ai.e-infra.cz/v1",
    },
    "openrouter": {
        "LLM_URL": "https://openrouter.ai/api/v1",
    },
    "nvidia": {
        "LLM_URL": "http://scl-nvidia-proxy:8448/v1",
        "LLM_MODEL": "nvidia/nemotron-3-ultra-550b-a55b",
    },
}

# ── Helpers ───────────────────────────────────────────────────────────


def _read_env() -> dict[str, str | None]:
    """Read credentials .env file, returning all key-value pairs.

    Falls back to process environment variables when the credentials file
    does not exist or does not contain a variable. This allows the plugin
    to validate and test connections out of the box when credentials are
    injected via docker-compose environment variables.
    """
    env: dict[str, str | None] = {}

    # Start with process environment for all known variables.
    for var in VARIABLE_SCHEMA:
        env[var["key"]] = os.getenv(var["key"])

    # Credentials saved through the UI take precedence over env vars.
    if CREDENTIALS_PATH.exists():
        file_values = dict(dotenv_values(CREDENTIALS_PATH))
        for key, val in file_values.items():
            if key in env:
                env[key] = val

    return env


def _write_env(updates: dict[str, str | None]) -> None:
    """Write updates to credentials .env, preserving comments and ordering."""
    CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    existing_keys: set[str] = set()

    if CREDENTIALS_PATH.exists():
        raw = CREDENTIALS_PATH.read_text(encoding="utf-8")
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                lines.append(line)
                continue
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)", stripped)
            if match:
                key = match.group(1)
                existing_keys.add(key)
                if key in updates:
                    val = updates[key]
                    if val is None or val == "":
                        lines.append(f"{key}=")
                    else:
                        lines.append(f"{key}={val}")
                    del updates[key]
                else:
                    lines.append(line)
            else:
                lines.append(line)

    # Append any new keys
    for key, val in updates.items():
        if val is None or val == "":
            lines.append(f"{key}=")
        else:
            lines.append(f"{key}={val}")

    CREDENTIALS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info(f"Credentials saved to {CREDENTIALS_PATH}")


# ── Request / Response Models ─────────────────────────────────────────


class EnvUpdate(BaseModel):
    values: dict[str, str | None]


class TestConnectionRequest(BaseModel):
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model: Optional[str] = None


# ── Endpoints ─────────────────────────────────────────────────────────


@router.get("/schema")
async def get_schema():
    """Return the full schema: groups, variables, and presets."""
    return {
        "groups": GROUPS,
        "variables": VARIABLE_SCHEMA,
        "presets": PROVIDER_PRESETS,
    }


@router.get("/credentials")
async def read_credentials():
    """Read current credential values. Passwords are masked."""
    env = _read_env()
    masked: dict[str, str] = {}
    for var in VARIABLE_SCHEMA:
        key = var["key"]
        val = env.get(key, "")
        if val and var.get("type") == "password":
            if len(val) > 8:
                masked[key] = "*" * (len(val) - 4) + val[-4:]
            else:
                masked[key] = "****"
        else:
            masked[key] = val or ""
    return {"values": masked}


@router.post("/credentials")
async def write_credentials(update: EnvUpdate):
    """Write credential values. Empty string clears the variable."""
    _write_env(update.values)
    return {"status": "ok"}


@router.get("/validate")
async def validate_credentials():
    """Check if required credentials are set."""
    env = _read_env()
    missing: list[str] = []
    for var in VARIABLE_SCHEMA:
        if var.get("required"):
            val = env.get(var["key"], "")
            if not val:
                missing.append(var["key"])
    return {"valid": len(missing) == 0, "missing": missing}


@router.post("/test-connection")
async def test_connection(req: Optional[TestConnectionRequest] = None):
    """Send a minimal request to the LLM provider to verify connectivity."""
    env = _read_env()

    api_key = (req.api_key if req and req.api_key else env.get("OPENCODE_API_KEY", "")).strip()
    base_url = (req.base_url if req and req.base_url else env.get("LLM_URL", "")).strip()
    model = (req.model if req and req.model else env.get("LLM_MODEL", "gpt-4o")).strip()

    if not api_key:
        return {"success": False, "error": "OPENCODE_API_KEY is not set."}
    if not base_url:
        return {"success": False, "error": "LLM_URL is not set."}

    base_url = base_url.rstrip("/")
    url = f"{base_url}/chat/completions"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with only the word: pong"}],
        "max_tokens": 10,
        "temperature": 0,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            elapsed = round(time.time() - start, 2)

            if resp.status_code == 200:
                data = resp.json()
                reply = ""
                choices = data.get("choices", [])
                if choices:
                    reply = choices[0].get("message", {}).get("content", "").strip()
                model_used = data.get("model", model)
                return {
                    "success": True,
                    "reply": reply,
                    "model": model_used,
                    "latency_s": elapsed,
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
                    "latency_s": elapsed,
                }

    except httpx.TimeoutException:
        return {"success": False, "error": "Request timed out (30s)."}
    except httpx.ConnectError:
        return {"success": False, "error": f"Connection failed. Check LLM_URL: {base_url}"}
    except Exception as e:
        return {"success": False, "error": str(e)[:500]}
