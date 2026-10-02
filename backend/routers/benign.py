"""
Benign Agent Router

Native dashboard API for the generalized benign agent: personality selection,
host/roster binding, prompt generation and topology patch application.

Endpoints (prefix /api/benign):
  GET  personalities               — the personality catalogue
  GET  topologies/{tid}            — topology annotated for benign placement
  POST preview                     — (personality, host, targets) -> prompt + patch
  POST apply                       — persist the patch via the topology plugin
                                     (+ optional topology restart)
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..services import benign_agent

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/benign", tags=["benign-agents"])


# =============================================================================
# Models
# =============================================================================

class BenignPreviewRequest(BaseModel):
    topology_id: str
    personality_id: str
    mode: str = Field(pattern="^(resident|remote)$")
    host_id: str
    operator: Optional[str] = None            # "new" | "existing:<host_id>"
    targets: List[str] = Field(default_factory=list)
    allow_internet: bool = False


class BenignApplyRequest(BaseModel):
    topology_id: str
    topology_patch: Dict[str, Any]
    restart: bool = False                      # regenerate containers if running


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/personalities")
async def list_personalities():
    """The benign personality catalogue (host-agnostic WHO the agent is)."""
    return {"personalities": benign_agent.load_personalities()}


@router.get("/topologies/{topology_id}")
async def get_annotated_topology(topology_id: str):
    """Topology annotated for benign placement (can-carry-agent, grants, exclusions)."""
    try:
        doc, running = await benign_agent.fetch_topology(topology_id)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 — surface plugin errors to the UI
        logger.error("benign annotate %s failed: %s", topology_id, e)
        raise HTTPException(status_code=502, detail=str(e))
    ann = benign_agent.annotate_topology(doc)
    ann["is_running"] = bool(running)
    return ann


@router.post("/preview")
async def preview_benign_agent(req: BenignPreviewRequest):
    """Compose (personality x host | fleet) into a full prompt + topology patch."""
    try:
        doc, _running = await benign_agent.fetch_topology(req.topology_id)
        payload = req.model_dump()
        payload["_doc"] = doc
        return benign_agent.build_preview(payload)
    except HTTPException:
        raise
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("benign preview failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/apply")
async def apply_benign_agent(req: BenignApplyRequest):
    """Persist a preview's topology_patch (agents, agent_config, host, firewall rules)."""
    try:
        return await benign_agent.apply_patch(req.model_dump())
    except HTTPException:
        raise
    except (ValueError, KeyError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # noqa: BLE001
        logger.exception("benign apply failed")
        raise HTTPException(status_code=500, detail=str(e))
