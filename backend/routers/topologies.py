"""
Topology Management Router

Provides API endpoints for integrating with the network-topology plugin.
Allows listing, viewing, starting, and stopping topologies.
Also loads hardcoded topologies from /app/topologies/ directory.
"""

import json
import logging
import os
from pathlib import Path
import httpx
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

# Configuration — resolved via env vars set in docker-compose.yml
TOPOLOGY_PLUGIN_URL = os.getenv(
    "TOPOLOGY_PLUGIN_URL", "http://scl-plugin-network-topology-control-plane:9002"
)
TOPOLOGIES_DIR = Path(os.getenv("TOPOLOGIES_DIR", "/app/topologies"))

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/topologies", tags=["topologies"])


# =============================================================================
# Models
# =============================================================================

class RouterInfo(BaseModel):
    """Router information in a topology."""
    id: str
    name: str
    parent_router_id: Optional[str] = None
    ssh_enabled: bool = False
    username: Optional[str] = None
    password: Optional[str] = None
    agents: List[str] = Field(default_factory=list)


class NetworkHost(BaseModel):
    """Host information in a network."""
    id: str
    name: str
    type: str
    image: str
    ssh_enabled: bool = False
    username: Optional[str] = None
    password: Optional[str] = None
    agents: List[str] = Field(default_factory=list)
    # Opt host into the guardrail/gate. None/absent = auto (armed iff a
    # guarded agent — coder56/soc_god — is present on the host). Declared here so
    # it round-trips through the plugin's topology.json (NetworkHost is the detail
    # sub-model; without this the detail/create response would 500 on the key).
    guardrail_enabled: Optional[bool] = Field(default=None)
    # Per-host coder56 verification mode. None/absent keeps the current default
    # (enabled); False restores direct single-agent finding validation.
    coder56_verifier_enabled: Optional[bool] = Field(default=None)
    # Per-assignment prompt/goal overrides ({agent_type: {system_prompt, goal}}),
    # consumed by the topology plugin at compose time (prepended to the baked
    # agent prompt; goal appended). Declared here so the GET detail response
    # round-trips it — without this field the dashboard's GET -> PUT save path
    # silently deleted hand-set or benign-wizard agent_config values.
    agent_config: Optional[Dict[str, Any]] = Field(default=None)
    generate_data: bool = False
    data_prompt: Optional[str] = None
    data_content: Optional[str] = None


class NetworkInfo(BaseModel):
    """Network information in a topology."""
    id: str
    name: str
    cidr: str
    internet: bool = False
    router_ids: List[str] = Field(default_factory=list)
    default_router_id: Optional[str] = None
    hosts: List[NetworkHost] = Field(default_factory=list)


class TopologySummary(BaseModel):
    """Summary information about a topology."""
    id: str
    name: str
    version: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    network_count: int = 0
    host_count: int = 0
    is_running: bool = False


class TopologyDetail(BaseModel):
    """Detailed information about a topology."""
    id: str
    name: str
    version: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    routers: List[RouterInfo] = Field(default_factory=list)
    networks: List[NetworkInfo] = Field(default_factory=list)
    infrastructure: Dict[str, Any] = Field(default_factory=dict)


class TopologyListResponse(BaseModel):
    """Response for listing topologies."""
    topologies: List[TopologySummary]


class TopologyStartResponse(BaseModel):
    """Response for starting a topology."""
    message: str
    topology_id: str
    job_id: Optional[str] = None


class TopologyStopResponse(BaseModel):
    """Response for stopping a topology."""
    message: str
    topology_id: str


class Coder56VerifierUpdate(BaseModel):
    """Persist and optionally apply the coder56 verifier mode for one host."""
    enabled: bool
    restart: bool = True


# =============================================================================
# Helper Functions
# =============================================================================

async def fetch_from_topology_plugin(path: str) -> Dict[str, Any]:
    """
    Fetch data from the network-topology plugin.

    Args:
        path: API path to fetch

    Returns:
        JSON response data

    Raises:
        HTTPException: If the request fails
    """
    url = f"{TOPOLOGY_PLUGIN_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error from topology plugin: {e}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error from topology plugin: {e.response.text}"
        )
    except httpx.RequestError as e:
        logger.error(f"Request error to topology plugin: {e}")
        raise HTTPException(
            status_code=503,
            detail="Topology plugin unavailable"
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


async def post_to_topology_plugin(path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Post data to the network-topology plugin.

    Args:
        path: API path to post to
        data: Optional JSON data to send

    Returns:
        JSON response data

    Raises:
        HTTPException: If the request fails
    """
    url = f"{TOPOLOGY_PLUGIN_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=data)
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error from topology plugin: {e}")
        raise HTTPException(
            status_code=e.response.status_code,
            detail=f"Error from topology plugin: {e.response.text}"
        )
    except httpx.RequestError as e:
        logger.error(f"Request error to topology plugin: {e}")
        raise HTTPException(
            status_code=503,
            detail="Topology plugin unavailable"
        )
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


def topology_to_summary(topology: Dict[str, Any]) -> TopologySummary:
    """Convert topology dict to summary model."""
    # Handle both summary format (from list endpoint) and detail format
    if isinstance(topology.get("networks"), int):
        # Summary format - networks and hosts are already counts
        network_count = topology.get("networks", 0)
        host_count = topology.get("hosts", 0)
    else:
        # Detail format - networks is an array
        networks = topology.get("networks", [])
        network_count = len(networks)
        host_count = sum(len(net.get("hosts", [])) for net in networks)

    return TopologySummary(
        id=topology.get("id", ""),
        name=topology.get("name", ""),
        version=topology.get("version", "2.0"),
        created_at=topology.get("created_at"),
        updated_at=topology.get("updated_at"),
        network_count=network_count,
        host_count=host_count,
        is_running=topology.get("running", False)
    )


def topology_to_detail(topology: Dict[str, Any]) -> TopologyDetail:
    """Convert topology dict to detail model."""
    routers = [RouterInfo(**r) for r in topology.get("routers", [])]
    networks = [NetworkInfo(**n) for n in topology.get("networks", [])]

    return TopologyDetail(
        id=topology.get("id", ""),
        name=topology.get("name", ""),
        version=topology.get("version", "2.0"),
        created_at=topology.get("created_at"),
        updated_at=topology.get("updated_at"),
        routers=routers,
        networks=networks,
        infrastructure=topology.get("infrastructure", {})
    )


def load_local_topologies() -> List[Dict[str, Any]]:
    """Load hardcoded topologies from the local topologies directory."""
    topologies = []
    if not TOPOLOGIES_DIR.exists():
        logger.warning(f"Topologies directory does not exist: {TOPOLOGIES_DIR}")
        return topologies

    for json_file in TOPOLOGIES_DIR.glob("*.json"):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                topology = json.load(f)
                topology['_source'] = 'local'  # Mark as local topology
                topologies.append(topology)
                logger.info(f"Loaded local topology: {topology.get('id', json_file.stem)}")
        except Exception as e:
            logger.error(f"Failed to load topology from {json_file}: {e}")

    return topologies


def load_local_topology(topology_id: str) -> Optional[Dict[str, Any]]:
    """Load a specific local topology by ID."""
    if not TOPOLOGIES_DIR.exists():
        return None

    json_file = TOPOLOGIES_DIR / f"{topology_id}.json"
    if not json_file.exists():
        return None

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            topology = json.load(f)
            topology['_source'] = 'local'
            return topology
    except Exception as e:
        logger.error(f"Failed to load local topology {topology_id}: {e}")
        return None


# =============================================================================
# API Endpoints
# =============================================================================

@router.get("", response_model=TopologyListResponse)
async def list_topologies():
    """
    List all available topologies.

    Returns a list of topology summaries including id, name, version,
    network/host counts, and running status.
    Includes both topologies from the network-topology plugin and local hardcoded topologies.
    """
    all_summaries = []

    # Load topologies from the network-topology plugin
    try:
        data = await fetch_from_topology_plugin("/api/topologies")
        plugin_topologies = data.get("topologies", [])
        all_summaries.extend([topology_to_summary(t) for t in plugin_topologies])
    except HTTPException as e:
        if e.status_code != 503:
            raise
        logger.warning("Topology plugin unavailable, using local topologies only")

    # Load local hardcoded topologies
    local_topologies = load_local_topologies()
    local_ids = {s.id for s in all_summaries}  # Avoid duplicates

    for t in local_topologies:
        if t.get("id") not in local_ids:
            all_summaries.append(topology_to_summary(t))

    return TopologyListResponse(topologies=all_summaries)


@router.post("", response_model=TopologyDetail)
async def create_topology(payload: Dict[str, Any]):
    """
    Create a brand-new topology. The network-topology plugin generates a fresh id
    (slugified name + uuid suffix) when the payload omits `id`. Minimal body:
    ``{"name": "...", "networks": [{"name": "lan", "hosts": [{"name": "host1"}]}]}``.
    Returns the newly created TopologyDetail.
    """
    try:
        saved_data = await post_to_topology_plugin("/api/topologies", payload)
        saved_topology = saved_data.get("topology", saved_data)
        return topology_to_detail(saved_topology)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating topology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{topology_id}", response_model=TopologyDetail)
async def get_topology(topology_id: str):
    """
    Get detailed information about a specific topology.

    Includes full network, router, and host configuration.
    First checks the network-topology plugin, then falls back to local topologies.
    """
    # Try to get from the network-topology plugin first
    try:
        data = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
        topology_data = data.get("topology", data)
        return topology_to_detail(topology_data)
    except HTTPException as e:
        if e.status_code != 404 and e.status_code != 503:
            raise
        logger.info(f"Topology {topology_id} not found in plugin, checking local topologies")

    # Fall back to local topologies
    local_topology = load_local_topology(topology_id)
    if local_topology:
        return topology_to_detail(local_topology)

    raise HTTPException(status_code=404, detail=f"Topology {topology_id} not found")


@router.put("/{topology_id}", response_model=TopologyDetail)
async def update_topology(topology_id: str, payload: Dict[str, Any]):
    """
    Update a topology's host agent assignments.

    Fetches the current full topology (preserving firewall rules, infrastructure, etc.),
    merges in the updated networks (which carry the new agents lists per host),
    then saves back to the network-topology plugin.
    If the topology is local-only, it will be saved to the plugin first.
    """
    try:
        # Try to fetch from plugin first
        try:
            current_data = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
            current_topology = current_data.get("topology", current_data)
        except HTTPException as e:
            if e.status_code == 404 or e.status_code == 503:
                # Topology not in plugin, load from local
                local_topology = load_local_topology(topology_id)
                if not local_topology:
                    raise HTTPException(status_code=404, detail=f"Topology {topology_id} not found")
                current_topology = local_topology
            else:
                raise

        # Merge in the updated networks (agents may have changed)
        if "networks" in payload:
            current_topology["networks"] = payload["networks"]

        # Ensure the ID is always set correctly
        current_topology["id"] = topology_id

        # Remove internal fields before saving
        current_topology.pop('_source', None)

        # Save to network-topology plugin
        saved_data = await post_to_topology_plugin("/api/topologies", current_topology)
        saved_topology = saved_data.get("topology", saved_data)
        return topology_to_detail(saved_topology)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{topology_id}/hosts/{host_id}/coder56-verifier")
async def update_coder56_verifier(
    topology_id: str,
    host_id: str,
    payload: Coder56VerifierUpdate,
):
    """Enable/disable coder56's independent verifier on a topology host.

    The setting is stored in topology.json. When ``restart`` is true, asking the
    topology plugin to start again regenerates compose and recreates the changed
    coder56 container, so the new OpenCode permissions/prompts take effect.
    """
    try:
        current_data = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
        topology = current_data.get("topology", current_data)

        target_host = None
        for network in topology.get("networks", []):
            for host in network.get("hosts", []):
                if host.get("id") == host_id:
                    target_host = host
                    break
            if target_host is not None:
                break

        if target_host is None:
            raise HTTPException(
                status_code=404,
                detail=f"Host {host_id} not found in topology {topology_id}",
            )
        if "coder56" not in (target_host.get("agents") or []):
            raise HTTPException(
                status_code=409,
                detail=f"Host {host_id} does not have coder56 assigned",
            )

        current_enabled = target_host.get("coder56_verifier_enabled") is not False
        changed = current_enabled != payload.enabled
        target_host["coder56_verifier_enabled"] = payload.enabled
        saved_data = await post_to_topology_plugin("/api/topologies", topology)

        start_data: Dict[str, Any] = {}
        if changed and payload.restart:
            start_data = await post_to_topology_plugin(
                f"/api/topologies/{topology_id}/start"
            )

        return {
            "topology_id": topology_id,
            "host_id": host_id,
            "enabled": payload.enabled,
            "changed": changed,
            "restarting": bool(changed and payload.restart),
            "job_id": start_data.get("job_id"),
            "message": start_data.get(
                "message",
                "Coder56 verifier setting saved"
                + (" and topology restart requested" if changed and payload.restart else ""),
            ),
            "topology": saved_data.get("topology", saved_data),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error updating coder56 verifier for %s/%s: %s",
            topology_id,
            host_id,
            e,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{topology_id}/start", response_model=TopologyStartResponse)
async def start_topology(topology_id: str):
    """
    Start a topology by launching its Docker containers.

    This will:
    1. Ensure the topology exists in the network-topology plugin (save if local-only)
    2. Generate docker-compose.yml
    3. Start containers with docker-compose up

    Returns a message and optional job_id for tracking progress.
    """
    try:
        # Check if topology exists in plugin, if not save it first
        try:
            await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
        except HTTPException as e:
            if e.status_code == 404 or e.status_code == 503:
                # Topology not in plugin, load from local and save
                local_topology = load_local_topology(topology_id)
                if not local_topology:
                    raise HTTPException(status_code=404, detail=f"Topology {topology_id} not found")
                local_topology.pop('_source', None)
                await post_to_topology_plugin("/api/topologies", local_topology)
                logger.info(f"Saved local topology {topology_id} to plugin before starting")
            else:
                raise

        # Now start the topology
        data = await post_to_topology_plugin(f"/api/topologies/{topology_id}/start")

        return TopologyStartResponse(
            message=data.get("message", "Topology started successfully"),
            topology_id=topology_id,
            job_id=data.get("job_id")
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{topology_id}/stop", response_model=TopologyStopResponse)
async def stop_topology(topology_id: str):
    """
    Stop a topology by stopping its Docker containers.

    Uses docker-compose down to stop all containers in the topology.
    """
    try:
        data = await post_to_topology_plugin(f"/api/topologies/{topology_id}/stop")

        return TopologyStopResponse(
            message=data.get("message", "Topology stopped successfully"),
            topology_id=topology_id
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{topology_id}/status")
async def get_topology_status(topology_id: str):
    """
    Get the current status of a topology.

    Returns information about running containers, agent states,
    and overall topology health.
    """
    try:
        # Get topology details — network-topology wraps in {"topology": {...}, "running": bool}
        data = await fetch_from_topology_plugin(f"/api/topologies/{topology_id}")
        is_running = data.get("running", False)
        topology = data.get("topology", data)

        networks = topology.get("networks", [])
        host_count = sum(len(net.get("hosts", [])) for net in networks)

        return {
            "topology_id": topology_id,
            "name": topology.get("name", ""),
            "host_count": host_count,
            "containers_running": 0,  # TODO: Get from docker
            "agents_assigned": 0,  # TODO: Count from topology
            "status": "running" if is_running else "stopped"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting topology status {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{topology_id}/jobs/{job_id}")
async def get_topology_job(topology_id: str, job_id: str):
    """
    Poll a start/stop background job from the topology plugin.

    The plugin runs start/stop asynchronously and returns a job_id; the job's
    status ('running' | 'completed' | 'failed') and, on failure, its ``error``
    (e.g. a docker-compose ``Pool overlaps`` subnet-collision message) are read
    here so the UI can surface why a start failed instead of silently showing
    'stopped'. ``topology_id`` is path context only and is not validated.
    """
    try:
        data = await fetch_from_topology_plugin(f"/api/jobs/{job_id}")
        return data.get("job") or {}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job {job_id} for topology {topology_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
