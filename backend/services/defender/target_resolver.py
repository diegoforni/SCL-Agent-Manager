"""Dynamic target resolution for the defender.

Replaces Trident's hardcoded ``determine_target_info()`` IP-prefix map
(``172.31.0.*`` -> server, ``172.30.0.*`` -> compromised). Hosts and their IPs
are dynamic — assigned by network-topology per CIDR — so resolution is done
against the running topology plus Docker labels at call time:

* a planner ``target_host`` (name) or an alert's victim IP is mapped to a
  defended host, then to its live container;
* alerts whose target matches no defended host are dropped by the policy gate
  (surfaced as a counter on ``/api/defender/status``).
"""
import logging
from typing import Any, Dict, List, Optional

from ..docker_client import create_docker_client, get_container_by_host_id, get_container_details
from ..topology_client import find_host
from .state import get_defender_store

logger = logging.getLogger(__name__)


async def _host_name(topology_id: str, host_id: str) -> str:
    try:
        host = find_host(topology_id, host_id)
        if host:
            return host.get("name", host_id)
    except Exception:
        pass
    return host_id


async def _container_ips(docker: Any, container_id: str) -> List[str]:
    """All IPs of a container across every attached network.

    A defended host sits on both its topology subnet and playground-net;
    SLIPS sees the topology-subnet IP while Docker's preferred IP is the
    playground-net one, so alert matching must consider ALL IPs.
    """
    try:
        # create_docker_client() returns a wrapper whose aiodocker client is at .docker
        # (same access pattern as docker_client.get_container_details).
        container = await docker.docker.containers.get(container_id)
        info = await container.show()
        nets = (info.get("NetworkSettings") or {}).get("Networks") or {}
        return [n.get("IPAddress") for n in nets.values() if n.get("IPAddress")]
    except Exception:
        return []


async def defended_manifest(topology_id: str) -> List[Dict[str, Any]]:
    """Return the defended hosts for ``topology_id`` with their live IPs.

    Each entry: ``{host_id, name, ip, ips}`` — ``ips`` is the full set across
    every attached network (used for alert matching); ``ip`` is the first/preferred
    one (for display). IPs come from the running container via Docker.
    """
    store = get_defender_store()
    policy = store.get_defended(topology_id)
    host_ids: List[str] = policy.get("host_ids") or []
    if not host_ids:
        return []

    out: List[Dict[str, Any]] = []
    try:
        async with create_docker_client() as docker:
            for host_id in host_ids:
                name = await _host_name(topology_id, host_id)
                ips: List[str] = []
                try:
                    container_id = await get_container_by_host_id(docker, topology_id, host_id)
                    if container_id:
                        ips = await _container_ips(docker, container_id)
                except Exception as exc:
                    logger.debug("could not resolve ips for host %s: %s", host_id, exc)
                out.append({
                    "host_id": host_id,
                    "name": name,
                    "ip": ips[0] if ips else "unknown",
                    "ips": ips,
                })
    except Exception as exc:
        logger.warning("docker unavailable while building defended manifest: %s", exc)
        for host_id in host_ids:
            out.append({"host_id": host_id, "name": await _host_name(topology_id, host_id), "ip": "unknown", "ips": []})
    return out


async def resolve_target_by_ip(topology_id: str, ip: str) -> Optional[Dict[str, Any]]:
    """Find the defended host whose live IPs contain ``ip`` (the alert's victim).

    Returns the host dict or ``None`` if no defended host matches — which the
    auto_responder treats as a policy drop.
    """
    if not ip:
        return None
    for host in await defended_manifest(topology_id):
        if ip in (host.get("ips") or []):
            return host
    return None


async def container_for_host(topology_id: str, host_id: str) -> Optional[str]:
    """Resolve a host_id to its live container_id (or None if not running)."""
    try:
        async with create_docker_client() as docker:
            return await get_container_by_host_id(docker, topology_id, host_id)
    except Exception as exc:
        logger.warning("could not resolve container for host %s: %s", host_id, exc)
        return None


def alert_text(alert: Dict[str, Any]) -> str:
    """Flatten a SLIPS alert into a single plaintext blob for the planner.

    Mirrors what Trident forwarded: the raw/description/threat_level plus the
    structured fields the planner needs (source/dest IP, attack id/type).
    """
    if not isinstance(alert, dict):
        return str(alert)
    parts = [
        f"attackid: {alert.get('attackid', alert.get('id', 'unknown'))}",
        f"attack_type: {alert.get('attack_type', alert.get('type', 'unknown'))}",
        f"sourceip: {alert.get('sourceip', alert.get('srcip', 'unknown'))}",
        f"destip: {alert.get('destip', alert.get('dstip', 'unknown'))}",
        f"threat_level: {alert.get('threat_level', alert.get('severity', 'unknown'))}",
        f"confidence: {alert.get('confidence', 'unknown')}",
        f"proto: {alert.get('proto', 'unknown')}",
    ]
    for key in ("description", "note", "raw"):
        val = alert.get(key)
        if val:
            parts.append(f"{key}: {val}")
    return "\n".join(parts)


def alert_destip(alert: Dict[str, Any]) -> Optional[str]:
    return alert.get("destip") or alert.get("dstip")


def alert_sourceip(alert: Dict[str, Any]) -> Optional[str]:
    return alert.get("sourceip") or alert.get("srcip")
