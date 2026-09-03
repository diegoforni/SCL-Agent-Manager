"""
Topology Client for Agent Manager

Single source of truth for topology data is the network-topology plugin, which
owns topology.json and exposes it over HTTP (TOPOLOGY_PLUGIN_URL). These helpers
read/write topology data *exclusively* through that API — the agent-manager has
no local topology file store. Agent assignments live in topology.json as
`host.agents` and are derived on demand (see agent_lifecycle), never persisted
separately.
"""

import asyncio
import logging
import os
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

# The topology plugin owns topology.json and serves it over HTTP.
TOPOLOGY_PLUGIN_URL = os.environ.get(
    'TOPOLOGY_PLUGIN_URL', 'http://scl-plugin-network-topology-control-plane:9002'
).rstrip('/')

# HTTP timeout for plugin calls (local network; keep short).
_PLUGIN_TIMEOUT = 15.0


class TopologyNotFound(Exception):
    """Raised when a topology does not exist in the plugin."""


def _api_get(path: str) -> Dict[str, Any]:
    """GET a JSON object from the topology plugin (sync)."""
    resp = httpx.get(f"{TOPOLOGY_PLUGIN_URL}{path}", timeout=_PLUGIN_TIMEOUT)
    if resp.status_code == 404:
        raise TopologyNotFound(path)
    resp.raise_for_status()
    return resp.json()


def _api_post(path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """POST JSON to the topology plugin (sync)."""
    resp = httpx.post(f"{TOPOLOGY_PLUGIN_URL}{path}", json=payload, timeout=_PLUGIN_TIMEOUT)
    resp.raise_for_status()
    return resp.json()


def list_topology_ids() -> list:
    """Return the IDs of all topologies known to the plugin."""
    data = _api_get("/api/topologies")
    return [t.get('id') for t in data.get('topologies', []) if t.get('id')]


def get_topology_path(topology_id: str) -> str:
    """Deprecated — topology data is served by the plugin over HTTP, not on disk.

    Kept so legacy imports don't break at import time; calling it is an error.
    """
    raise NotImplementedError(
        "Topology data is served by the network-topology plugin over HTTP; "
        "there is no local topology file path. Use load_topology() instead."
    )


def load_topology(topology_id: str, topology_path: Optional[str] = None) -> Dict[str, Any]:
    """Load a topology from the plugin HTTP API.

    Args:
        topology_id: The ID of the topology to load.
        topology_path: Ignored (kept for backward-compatible signature).

    Returns:
        Parsed topology dictionary.

    Raises:
        TopologyNotFound: If the topology does not exist.
        httpx.HTTPError: On transport/HTTP errors.
    """
    data = _api_get(f"/api/topologies/{topology_id}")
    return data['topology']


def save_topology(topology_id: str, topology: Dict[str, Any], topology_path: Optional[str] = None) -> None:
    """Save a topology via the plugin HTTP API.

    Callers perform read-modify-write (load full topology, mutate `host.agents`,
    save full topology), so the complete document is sent back and no fields are
    lost.

    Args:
        topology_id: The ID of the topology (also expected as `id` in the payload).
        topology: Full topology dictionary to save.
        topology_path: Ignored (kept for backward-compatible signature).

    Raises:
        httpx.HTTPError: On transport/HTTP errors.
    """
    # Ensure the payload carries its id; the plugin keys storage off it.
    if not topology.get('id'):
        topology = {**topology, 'id': topology_id}
    _api_post("/api/topologies", topology)


def find_host(topology_id: str, host_id: str, topology_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Locate a host by its ID within a topology (loaded from the plugin).

    Args:
        topology_id: The ID of the topology.
        host_id: The ID of the host to find (e.g., "kali-host-01").
        topology_path: Ignored (kept for backward-compatible signature).

    Returns:
        Host dictionary if found, None otherwise.
    """
    topology = load_topology(topology_id, topology_path)

    # Search in top-level hosts
    if 'hosts' in topology:
        for host in topology['hosts']:
            if host.get('id') == host_id:
                return host

    # Search in networks (also called subnets in some topologies)
    for key in ['networks', 'subnets']:
        if key in topology:
            for network in topology[key]:
                if 'hosts' in network:
                    for host in network['hosts']:
                        if host.get('id') == host_id:
                            return host

    return None


def regenerate_compose(topology_id: Optional[str] = None, compose_path: Optional[str] = None) -> Dict[str, Any]:
    """No-op stub. The plugin regenerates compose on start; agent assignments
    are already reflected in topology.json and are picked up by container
    discovery.

    Args:
        topology_id: Optional topology ID to regenerate.
        compose_path: Optional path to docker-compose.yml.

    Returns:
        Dictionary with 'success' (bool) and 'message' (str) keys.
    """
    return {
        'success': True,
        'message': 'Topology updated (agent assignment persisted to topology.json)'
    }


async def restart_topology_async(topology_id: str) -> Dict[str, Any]:
    """Ask the network-topology plugin to (re)start a topology.

    The plugin owns docker-compose.yml and the container lifecycle, so the
    agent-manager must not try to run docker-compose itself. A restart applies
    any agent assignment changes that were saved to topology.json.

    Args:
        topology_id: The ID of the topology to restart.

    Returns:
        Plugin response dict (usually {'status': 'started'}).

    Raises:
        httpx.HTTPError: On transport/HTTP errors.
    """
    logger.info(f"Requesting topology restart from plugin: {topology_id}")
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(f"{TOPOLOGY_PLUGIN_URL}/api/topologies/{topology_id}/start")
        resp.raise_for_status()
        return resp.json()


def get_service_name(topology_id: str, host_id: str, topology_path: Optional[str] = None) -> Optional[str]:
    """Convert a host_id to its docker-compose service name.

    Args:
        topology_id: The ID of the topology.
        host_id: The ID of the host (e.g., "kali-host-01").
        topology_path: Ignored (kept for backward-compatible signature).

    Returns:
        Docker-compose service name if found, None otherwise.
    """
    host = find_host(topology_id, host_id, topology_path)
    if not host:
        return None

    # Check if service_name is explicitly defined
    if 'service_name' in host:
        return host['service_name']

    # Generate service name from host_id
    # Common pattern: "kali-host-01" -> "kali-host-01" or "kali_host_01"
    return host_id.replace('_', '-')
