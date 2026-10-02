"""Unit tests for the benign agent service (pure functions — no plugin HTTP)."""

import pytest

from backend.services.benign_agent import (
    mutate_topology,
    resolve_grant_ids,
    CARRIER,
    GRANTS,
)


@pytest.fixture
def sample_doc():
    return {
        "id": "t1", "name": "test",
        "networks": [
            {"id": "server", "cidr": "192.168.1.0/24", "hosts": [
                {"id": "web-server", "type": "vuln-web-server", "username": "webadmin",
                 "password": "admin123", "ssh_enabled": True, "ip_override": "192.168.1.4"},
                {"id": "other-server-1", "type": "normal-user", "username": "opsadmin",
                 "password": "pw", "ssh_enabled": True},
            ]},
            {"id": "backend", "cidr": "192.168.3.0/24", "hosts": [
                {"id": "db-server", "type": "db-server", "ssh_enabled": True,
                 "ip_override": "192.168.3.3"},
            ]},
        ],
        "router": {"firewall": {"allowed": ["client/client-1->server/web-server"]}},
    }


def test_grant_resolution(sample_doc):
    _, web, _ = None, None, None
    for net in sample_doc["networks"]:
        for h in net["hosts"]:
            if h["id"] == "web-server":
                web = h
            if h["id"] == "db-server":
                db = h
            if h["id"] == "other-server-1":
                ops = h
    assert resolve_grant_ids(web) == ["web-http", "web-ssh"]
    assert resolve_grant_ids(db) == ["db-sql-remote", "db-ssh"]
    assert resolve_grant_ids(ops) == ["ops-ssh"]
    assert resolve_grant_ids({**ops, "id": "some-box"}) == ["ssh-from-topology"]
    assert resolve_grant_ids({**ops, "id": "quiet-box", "ssh_enabled": False}) == []
    assert resolve_grant_ids({**ops, "id": "attacker"}) == []  # excluded host


def test_dedicated_image_types_match_compose():
    from backend.services.benign_agent import DEDICATED_IMAGE_TYPES
    # must mirror compose.py's dedicated-image branches exactly (host type wins
    # over agent presence there, so these hosts cannot carry the agent runtime)
    assert DEDICATED_IMAGE_TYPES == {
        "repo-server", "ad-server", "windows-client", "vuln-web-server",
        "smb-server", "coder56-mcp", "erpnext-server", "db-server",
    }


def test_addressing_matches_plugin_netmath(sample_doc):
    # plugin convention: router = last usable (.254), auto hosts from .11 upward
    # (netmath.host_ip offset = 10+index-1 % usable + 1, 1-based index)
    from backend.services.benign_agent import free_ip, host_ip
    server_net = sample_doc["networks"][0]
    assert host_ip(server_net, server_net["hosts"][0], 1) == "192.168.1.4"   # ip_override wins
    assert host_ip(server_net, {"id": "x"}, 1) == "192.168.1.11"             # first auto
    assert host_ip(server_net, {"id": "x"}, 2) == "192.168.1.12"             # second auto
    assert free_ip(server_net, sample_doc) == "192.168.1.10"                 # below auto window
    server_net["hosts"].append({"id": "pinned", "type": "normal-user",
                                "ip_override": "192.168.1.10"})
    assert free_ip(server_net, sample_doc) == "192.168.1.9"                  # skips taken .10


def test_mutate_assigns_agent_and_config(sample_doc):
    patch = {"home": {"host_id": "other-server-1", "network_id": "server", "new_host": None,
                      "system_prompt": "P2", "goal": "G2"},
             "firewall_rules": []}
    new_doc, changes = mutate_topology(sample_doc, patch)
    host = next(h for n in new_doc["networks"] for h in n["hosts"] if h["id"] == "other-server-1")
    assert host["agents"] == [CARRIER]
    assert host["agent_config"][CARRIER] == {"system_prompt": "P2", "goal": "G2"}
    # original untouched (deep copy semantics)
    orig = next(h for n in sample_doc["networks"] for h in n["hosts"] if h["id"] == "other-server-1")
    assert "agent_config" not in orig


def test_mutate_creates_host_and_dedups_rules(sample_doc):
    patch = {"home": {"host_id": "ops-workstation", "network_id": "server",
                      "new_host": {"id": "ops-workstation", "name": "ops-workstation",
                                   "type": "normal-user", "agents": [CARRIER],
                                   "ip_override": "192.168.1.10",
                                   "agent_config": {CARRIER: {"system_prompt": "P", "goal": "G"}}},
                      "system_prompt": "P", "goal": "G"},
             "firewall_rules": ["server/ops-workstation->backend/db-server",
                                "server/ops-workstation->backend/db-server"]}
    new_doc, changes = mutate_topology(sample_doc, patch)
    assert len(changes) == 3  # host created + config set + one (deduped) rule
    assert new_doc["router"]["firewall"]["allowed"].count(
        "server/ops-workstation->backend/db-server") == 1
    assert sample_doc["router"]["firewall"]["allowed"] == ["client/client-1->server/web-server"]
