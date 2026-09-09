"""
Starter Preset Router

Proxies the network-topology plugin's preset catalogue to the dashboard.
Starter topologies ship in the plugin's presets/ directory; a fresh clone of
the plugin starts with exactly those and no saved topologies. They are listed
here via GET /api/presets and materialized into a new draft topology via
POST /api/presets/{preset_id}/instantiate.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .topologies import (
    TopologyDetail,
    fetch_from_topology_plugin,
    post_to_topology_plugin,
    topology_to_detail,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/presets", tags=["presets"])


# =============================================================================
# Models
# =============================================================================

class PresetSummary(BaseModel):
    """Starter topology preset metadata (from the plugin's presets/ dir)."""
    preset_id: str
    preset_name: str
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    network_count: int = 0
    host_count: int = 0


class PresetListResponse(BaseModel):
    """Response for listing starter presets."""
    presets: List[PresetSummary]


class PresetInstantiateRequest(BaseModel):
    """Optional overrides when materializing a preset.

    Both fields optional: with neither, the plugin mints a fresh slug-based
    topology id (so repeated instantiations never collide) and keeps the
    preset's own topology name.
    """
    new_id: Optional[str] = None
    name: Optional[str] = None


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=PresetListResponse)
async def list_presets():
    """List the starter topology presets shipped with the plugin."""
    try:
        data = await fetch_from_topology_plugin("/api/presets")
        presets = [PresetSummary(**p) for p in data.get("presets", [])]
        return PresetListResponse(presets=presets)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing presets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{preset_id}/instantiate", response_model=TopologyDetail)
async def instantiate_preset(preset_id: str, payload: Optional[PresetInstantiateRequest] = None):
    """
    Materialize a starter preset into a new draft topology.

    Returns the newly created TopologyDetail (same shape as POST /api/topologies).
    """
    body = payload.model_dump(exclude_none=True) if payload else {}
    try:
        saved_data = await post_to_topology_plugin(
            f"/api/presets/{preset_id}/instantiate", body
        )
        saved_topology = saved_data.get("topology", saved_data)
        return topology_to_detail(saved_topology)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error instantiating preset '{preset_id}': {e}")
        raise HTTPException(status_code=500, detail=str(e))
