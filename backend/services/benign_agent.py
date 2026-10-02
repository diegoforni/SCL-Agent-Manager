"""
Benign Agent Service

Implements the generalized benign agent: (personality x host | fleet) -> a complete
system prompt, plus the topology patch that installs it. Port of the standalone
Benign Agent Console backend, integrated with the Agent Manager's topology-plugin
helpers so it reads/writes the same topology.json the rest of the plugin uses.

Placement logic encodes the deployment reality (compose.py picks dedicated images
for typed hosts BEFORE the agent branch, and those images have no OpenCode runtime):
  * generic host selected  -> the agent can run there (resident);
  * service host selected  -> the agent runs on an operator host (existing generic
    host, or a newly created one) and connects to the service host remotely;
    cross-subnet connections get explicit host-scoped firewall rules.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..routers.topologies import (  # reuses the plugin client + env config
    fetch_from_topology_plugin,
    post_to_topology_plugin,
)
from ..benign_framework import generate

CARRIER = "db_admin"  # the deployment's only unguarded benign slot (observer maps it to benign_agent/)
DEDICATED_IMAGE_TYPES = {
    "repo-server", "ad-server", "windows-client", "vuln-web-server",
    "smb-server", "coder56-mcp", "erpnext-server", "db-server",
}

_FRAMEWORK_DIR = Path(__file__).resolve().parent.parent / "benign_framework"
GRANTS = json.loads((_FRAMEWORK_DIR / "grants_library.json").read_text())
SERVICE_LABELS = {
    "ssh": ("sshd", 22), "database": ("PostgreSQL", 5432), "smb": ("Samba share", 445),
    "http": ("web server", 80), "directory": ("directory services (LDAP/Kerberos/SMB)", 389),
}


# ---------------------------------------------------------------------------
# personalities / grants
# ---------------------------------------------------------------------------

def load_personalities() -> List[Dict[str, Any]]:
    raw = generate.load("personalities.json")["personalities"]
    return [{"id": p["id"], "label": p["label"],
             "name": p["persona"]["name"], "role_title": p["persona"]["role_title"],
             "shift": p["persona"]["shift"], "multi_host": bool(p.get("multi_host"))}
            for p in raw]


def get_personality(pid: str) -> Dict[str, Any]:
    for p in generate.load("personalities.json")["personalities"]:
        if p["id"] == pid:
            return p
    raise ValueError(f"unknown personality: {pid}")


def resolve_grant_ids(host: Dict[str, Any]) -> List[str]:
    hid, htype = host["id"], host.get("type", "")
    if hid in GRANTS["ungrantable"] or htype in GRANTS["ungrantable"]:
        return []
    if hid in GRANTS["by_host"]:
        return list(GRANTS["by_host"][hid]["grants"])
    ids = GRANTS.get("type_fallbacks", {}).get(htype, [])
    if ids == ["ssh-from-topology"] and not host.get("ssh_enabled"):
        return []
    return ids


# ---------------------------------------------------------------------------
# topology access + annotation
# ---------------------------------------------------------------------------

async def fetch_topology(tid: str) -> Tuple[Dict[str, Any], Optional[bool]]:
    data = await fetch_from_topology_plugin(f"/api/topologies/{tid}")
    if isinstance(data, dict) and "topology" in data:
        return data["topology"], bool(data.get("running"))
    return data, None


def _net(cidr: str):
    import ipaddress
    return ipaddress.ip_network(str(cidr), strict=False)


def plugin_host_ip(cidr: str, host_index: int, host: Dict[str, Any] | None = None) -> str:
    """Exact port of the plugin's netmath.host_ip (ip_override wins, else the
    deterministic offset scheme starting at network+11, 1-based host_index)."""
    import ipaddress
    if host:
        override = str(host.get("ip_override") or "").strip()
        if override:
            try:
                if ipaddress.ip_address(override) in _net(cidr):
                    return override
            except ValueError:
                pass
    n = _net(cidr)
    usable = n.num_addresses - 2
    if usable <= 0:
        raise ValueError(f"network {cidr} is too small to address hosts")
    offset = (10 + int(host_index) - 1) % usable + 1
    return str(n.network_address + offset)


def host_ip(net: Dict[str, Any], host: Dict[str, Any], index: int) -> str:
    """index is 1-based (matches compose.py enumerate(..., start=1))."""
    return plugin_host_ip(net["cidr"], index, host)


def annotate_topology(doc: Dict[str, Any]) -> Dict[str, Any]:
    nets = []
    for net in doc.get("networks", []):
        hosts = []
        for i, h in enumerate(net.get("hosts", []), start=1):
            hosts.append({
                "id": h["id"], "type": h.get("type"), "ip": host_ip(net, h, i),
                "can_carry_agent": h.get("type") not in DEDICATED_IMAGE_TYPES,
                "agents": h.get("agents", []),
                "ssh_enabled": bool(h.get("ssh_enabled")),
                "known_grants": resolve_grant_ids(h),
                "excluded_reason": GRANTS["ungrantable"].get(h["id"])
                or GRANTS["ungrantable"].get(h.get("type")),
            })
        nets.append({"id": net["id"], "name": net.get("name"),
                     "cidr": net.get("cidr"), "hosts": hosts})
    return {"id": doc.get("id"), "name": doc.get("name"), "networks": nets}


def find_host(doc: Dict[str, Any], hid: str, required: bool = True):
    for net in doc["networks"]:
        for i, h in enumerate(net.get("hosts", []), start=1):
            if h["id"] == hid:
                return net, h, i
    if required:
        raise ValueError(f"host '{hid}' not found in topology")
    return None, None, None


def free_ip(net: Dict[str, Any], doc: Dict[str, Any]) -> str:
    """Pick an address BELOW the plugin's auto-assign window (which starts at
    network+11): scan .10 downward, skipping the router (.254-equivalent), the
    hackerlab console (.2), pinned overrides and computed host addresses. This
    keeps new operator hosts collision-free even if more hosts are added later
    (the auto window grows upward from .11, never downward)."""
    n = _net(net["cidr"])
    taken = {str(n.network_address + 2)}          # hackerlab console (.2)
    taken.add(str(n.broadcast_address - 1))       # router
    for h in net.get("hosts", []):
        if h.get("ip_override"):
            taken.add(str(h["ip_override"]).strip())
    for i, h in enumerate(net.get("hosts", []), start=1):
        if not h.get("ip_override"):
            taken.add(plugin_host_ip(net["cidr"], i))
    for cand in range(10, 2, -1):
        ip = str(n.network_address + cand)
        if ip not in taken:
            return ip
    raise ValueError(f"no free address below the auto-assign window in {net['cidr']}")


# ---------------------------------------------------------------------------
# spec assembly
# ---------------------------------------------------------------------------

def build_target(doc: Dict[str, Any], net: Dict[str, Any], host: Dict[str, Any],
                 index: int, home: Dict[str, Any], warnings: List[str]) -> Optional[Dict[str, Any]]:
    ids = resolve_grant_ids(host)
    if not ids:
        warnings.append(f"target '{host['id']}' skipped: no remote check template "
                        f"({GRANTS['ungrantable'].get(host['id'], host.get('type'))})")
        return None
    grants = []
    kinds = []
    for gid in ids:
        g = GRANTS["grants"].get(gid) or GRANTS["generic_grants"][gid]
        g = json.loads(json.dumps(g))
        g.setdefault("id", gid)
        for k, v in g["env"].items():
            if v == "<host-ip>":
                g["env"][k] = host_ip(net, host, index)
            elif v == "<from-topology>":
                key = "USER" if k.endswith("USER") else "PASSWORD"
                g["env"][k] = host.get("username" if key == "USER" else "password", "<set-me>")
        grants.append(g)
        kinds.append(g["kind"])
    if home["network_id"] == net["id"]:
        reach = "Same subnet as your home base (bridge-local)."
    else:
        reach = (f"Declared firewall path: {home['network_id']}/{home['host_id']}"
                 f"->{net['id']}/{host['id']}.")
    duties = [d for k in kinds for d in GRANTS["duty_phrases"][k]]
    services, seen = [], set()
    for k in kinds:
        if k not in seen:
            seen.add(k)
            services.append({"name": SERVICE_LABELS[k][0], "port": SERVICE_LABELS[k][1],
                             "details": ""})
    return {"host_id": host["id"], "network_id": net["id"], "ip": host_ip(net, host, index),
            "reach": reach, "services": services, "access_grants": grants, "duties": duties,
            "label": (GRANTS["by_host"].get(host["id"], {}).get("label") or host.get("type", ""))}


def resolve_home(doc: Dict[str, Any], req: Dict[str, Any],
                 warnings: List[str]) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    net, host, idx = find_host(doc, req["host_id"])
    mode = req["mode"]
    if mode == "resident":
        if host["type"] in DEDICATED_IMAGE_TYPES:
            raise ValueError(
                f"'{host['id']}' is a dedicated-image host (type '{host['type']}'): "
                "compose gives it a service image with no agent runtime. Use remote "
                "placement: the agent runs on an operator host and connects here.")
        home = {"host_id": host["id"], "network_id": net["id"], "ip": host_ip(net, host, idx),
                "host_type": host["type"], "role_label": f"Agent home base ({host['id']})",
                "local_account": {"user": host.get("username", "student"),
                                  "password": host.get("password", ""),
                                  "ssh_enabled": bool(host.get("ssh_enabled")),
                                  "note": "Your own machine."}}
        return home, None

    op = req.get("operator") or "new"
    if op.startswith("existing:"):
        onet, ohost, oidx = find_host(doc, op.split(":", 1)[1])
        if ohost["type"] in DEDICATED_IMAGE_TYPES:
            raise ValueError(f"operator host '{ohost['id']}' cannot carry an agent "
                             f"(dedicated image type '{ohost['type']}').")
        home = {"host_id": ohost["id"], "network_id": onet["id"],
                "ip": host_ip(onet, ohost, oidx), "host_type": ohost["type"],
                "role_label": "Operations workstation (agent home base)",
                "local_account": {"user": ohost.get("username", "student"),
                                  "password": ohost.get("password", ""),
                                  "ssh_enabled": bool(ohost.get("ssh_enabled")),
                                  "note": "Your own machine; keep your toolbox here."}}
        return home, None

    base = "ops-workstation"
    hid, n = base, 1
    while find_host(doc, hid, required=False)[1] is not None:
        n += 1
        hid = f"{base}-{n}"
    ip = free_ip(net, doc)
    home = {"host_id": hid, "network_id": net["id"], "ip": ip, "host_type": "normal-user",
            "role_label": "Operations workstation (agent home base)",
            "local_account": {"user": "opsuser", "password": "pr3p4re-r0unds",
                              "ssh_enabled": True,
                              "note": "Your own machine; keep your toolbox here."}}
    new_host = {"id": hid, "name": hid, "type": "normal-user", "image": "ubuntu:24.04",
                "ssh_enabled": True, "username": "opsuser", "password": "pr3p4re-r0unds",
                "generate_data": False, "agent_enabled": True, "agents": [CARRIER],
                "ip_override": ip}
    warnings.append(f"new operator host '{hid}' ({ip}) will be created on the "
                    f"{net['id']} network; it only exists after Apply + topology restart")
    return home, new_host


def assemble_fleet_spec(doc: Dict[str, Any], home: Dict[str, Any], target_ids: List[str],
                        allow_internet: bool, warnings: List[str]):
    targets, rules = [], []
    for tid in target_ids:
        net, host, idx = find_host(doc, tid, required=False)
        if net is None:
            warnings.append(f"target '{tid}' not found — skipped")
            continue
        if host["id"] == home["host_id"]:
            warnings.append(f"'{tid}' is the home base itself — skipped as target")
            continue
        t = build_target(doc, net, host, idx, home, warnings)
        if t is None:
            continue
        if net["id"] != home["network_id"]:
            rules.append(f"{home['network_id']}/{home['host_id']}->{net['id']}/{host['id']}")
        targets.append(t)
    if allow_internet:
        rules.append(f"{home['network_id']}/{home['host_id']}->internet")
    deduped = []
    for r in rules:
        if r not in deduped:
            deduped.append(r)
    return targets, deduped


def build_preview(req: Dict[str, Any]) -> Dict[str, Any]:
    """Async entry point is in the router; this is the synchronous core."""
    personality = get_personality(req["personality_id"])
    warnings: List[str] = []
    doc = req["_doc"]
    home, new_host = resolve_home(doc, req, warnings)
    targets, fw_rules = assemble_fleet_spec(doc, home, req.get("targets", []),
                                            bool(req.get("allow_internet")), warnings)
    nets = {"networks": {n["id"]: n["cidr"] for n in doc["networks"]}}

    if req["mode"] == "resident":
        net, host, idx = find_host(doc, req["host_id"])
        self_target = build_target(doc, net, host, idx, home, warnings)
        if self_target is None:
            raise ValueError(f"no access grants available for '{host['id']}' "
                             f"(type '{host['type']}'); use remote placement instead")
        binding = {"id": host["id"], "network_id": net["id"], "ip": host_ip(net, host, idx),
                   "host_type": host["type"],
                   "role_label": GRANTS["by_host"].get(host["id"], {}).get(
                       "label", host.get("type", "host")),
                   "capabilities": sorted({GRANTS["capability_of_kind"][
                       (GRANTS["grants"].get(g) or GRANTS["generic_grants"][g])["kind"]]
                       for g in resolve_grant_ids(host)} | {"linux"}),
                   "local_account": home["local_account"],
                   "services": self_target["services"],
                   "suggested_personality": personality["id"],
                   "access_grants": self_target["access_grants"],
                   "network_reach": {"allowed": ["local services only"], "denied":
                                     "everything remote unless a duty requires it"},
                   "host_constraints": []}
        prompt = generate.build_system_prompt(personality, binding, nets)
        goal = generate.build_goal(personality, binding, nets)
        roster: List[str] = []
        env: Dict[str, str] = {}
        for g in binding["access_grants"]:
            env.update(g.get("env", {}))
    else:
        if not targets:
            raise ValueError("no usable targets: pick at least one host the agent "
                             "should connect to")
        fleet = {"fleet_id": "dashboard-generalist", "label": "Dashboard-generated fleet",
                 "topology": nets, "home_base": home,
                 "firewall_rules_to_add": fw_rules, "targets": targets}
        prompt = generate.build_system_prompt_fleet(personality, fleet)
        goal = generate.build_goal_fleet(personality, fleet)
        roster = [t["host_id"] for t in targets]
        env = {}
        for t in targets:
            for g in t["access_grants"]:
                env.update(g.get("env", {}))

    patch = {"home": {"host_id": home["host_id"], "network_id": home["network_id"],
                      "new_host": (dict(new_host, agent_config={
                          CARRIER: {"system_prompt": prompt, "goal": goal}})
                          if new_host else None),
                      "system_prompt": prompt, "goal": goal},
             "firewall_rules": fw_rules if req["mode"] == "remote" else []}
    return {"topology_id": req["topology_id"], "personality_id": personality["id"],
            "mode": req["mode"], "home": home, "roster": roster,
            "system_prompt": prompt, "goal": goal, "env": env,
            "topology_patch": patch, "warnings": warnings}


# ---------------------------------------------------------------------------
# topology mutation + persistence
# ---------------------------------------------------------------------------

def mutate_topology(doc: Dict[str, Any], patch: Dict[str, Any],
                    carrier: str = CARRIER) -> Tuple[Dict[str, Any], List[str]]:
    import copy
    doc = copy.deepcopy(doc)
    changes: List[str] = []
    home = patch["home"]
    if not isinstance(home, dict) or not home.get("host_id") or not home.get("network_id"):
        raise ValueError("patch.home must carry host_id and network_id")
    new_host = home.get("new_host")
    if new_host is not None and not isinstance(new_host, dict):
        raise ValueError("patch.home.new_host must be an object or null")
    if not isinstance(home.get("system_prompt"), str) or not isinstance(home.get("goal"), str):
        raise ValueError("patch.home.system_prompt and .goal must be strings")
    for r in patch.get("firewall_rules", []):
        if not isinstance(r, str) or "->" not in r:
            raise ValueError(f"invalid firewall rule: {r!r}")
    matches = [n for n in doc["networks"] if n["id"] == home["network_id"]]
    if not matches:
        raise ValueError(f"network '{home['network_id']}' not found in topology")
    net = matches[0]
    if home.get("new_host"):
        if find_host(doc, home["host_id"], required=False)[1] is None:
            net.setdefault("hosts", []).append(json.loads(json.dumps(home["new_host"])))
            changes.append(f"created host {home['host_id']} on network {net['id']}")
    _, host, _ = find_host(doc, home["host_id"])
    agents = host.setdefault("agents", [])
    if carrier not in agents:
        agents.append(carrier)
        host["agent_enabled"] = True
        changes.append(f"assigned agent '{carrier}' to {home['host_id']}")
    host.setdefault("agent_config", {})[carrier] = {
        "system_prompt": home["system_prompt"], "goal": home["goal"]}
    changes.append(f"set agent_config['{carrier}'] on {home['host_id']} "
                   f"(prompt {len(home['system_prompt'])} chars)")
    router = doc.get("router") or {}
    fw = (router.get("firewall") or {}).get("allowed")
    if fw is None:
        raise ValueError("topology has no router.firewall.allowed to extend")
    for r in patch.get("firewall_rules", []):
        if r not in fw:
            fw.append(r)
            changes.append(f"firewall rule added: {r}")
    doc["updated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return doc, changes


async def apply_patch(payload: Dict[str, Any]) -> Dict[str, Any]:
    doc, running = await fetch_topology(payload["topology_id"])
    new_doc, changes = mutate_topology(doc, payload["topology_patch"])
    saved = await post_to_topology_plugin("/api/topologies", new_doc)
    saved_topology = saved.get("topology", saved)
    changes.append("topology saved via topology-plugin REST")
    restart_note = "will take effect at next topology start"
    if payload.get("restart") and running:
        from .topology_client import restart_topology_async
        restart_result = await restart_topology_async(payload["topology_id"])
        changes.append(f"topology restarted: {json.dumps(restart_result)[:200]}")
        restart_note = "topology restarted — containers regenerated with the new config"
    elif payload.get("restart"):
        restart_note = "topology not running — will take effect at start"
    changes.append(restart_note)
    return {"ok": True, "changes": changes, "topology": saved_topology}
