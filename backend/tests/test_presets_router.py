"""Tests for the starter-preset router.

GET /api/presets lists the plugin's presets/ catalogue; POST
/api/presets/{id}/instantiate materializes one into a draft topology. Both are
thin proxies over the network-topology plugin — everything external is
monkeypatched, no plugin or containers are needed.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.routers import presets as p


def _client(monkeypatch, *, fetch=None, post=None):
    """App with only the presets router, plugin helpers patched."""
    if fetch is not None:
        monkeypatch.setattr(p, "fetch_from_topology_plugin", fetch)
    if post is not None:
        monkeypatch.setattr(p, "post_to_topology_plugin", post)
    app = FastAPI()
    app.include_router(p.router)
    return TestClient(app)


def _saved_topology():
    """Minimal plugin save_topology() shape (what instantiate returns)."""
    return {
        "id": "two-nets-9f01aa",
        "name": "Two Nets",
        "version": "1.0",
        "networks": [
            {"id": "server", "name": "Server Network", "cidr": "192.168.1.0/24",
             "hosts": [{"id": "smb", "name": "smb", "type": "smb-server", "image": "ubuntu:24.04"}]},
            {"id": "client", "name": "Client Network", "cidr": "192.168.2.0/24", "hosts": []},
        ],
        "routers": [],
        "infrastructure": {},
    }


async def _fetch_presets(path):
    assert path == "/api/presets"
    return {"presets": [
        {"preset_id": "two-nets", "preset_name": "Two Nets",
         "description": "server + client subnets", "tags": ["training"],
         "network_count": 3, "host_count": 11},
        # wrapper counts missing → must default, not crash
        {"preset_id": "tiny", "preset_name": "Tiny"},
    ]}


def test_list_presets(monkeypatch):
    client = _client(monkeypatch, fetch=_fetch_presets)
    resp = client.get("/api/presets")
    assert resp.status_code == 200
    body = resp.json()
    assert [x["preset_id"] for x in body["presets"]] == ["two-nets", "tiny"]
    tiny = body["presets"][1]
    assert tiny["network_count"] == 0 and tiny["host_count"] == 0
    assert tiny["tags"] == [] and tiny["description"] == ""


def test_list_presets_plugin_down(monkeypatch):
    from fastapi import HTTPException

    async def boom(path):
        raise HTTPException(status_code=503, detail="plugin unreachable")

    client = _client(monkeypatch, fetch=boom)
    assert client.get("/api/presets").status_code == 503


def test_instantiate_preset(monkeypatch):
    async def do_post(path, data=None):
        assert path == "/api/presets/two-nets/instantiate"
        assert data == {"name": "My Two Nets"}  # new_id omitted → minted by plugin
        return {"topology": _saved_topology()}

    client = _client(monkeypatch, post=do_post)
    resp = client.post("/api/presets/two-nets/instantiate", json={"name": "My Two Nets"})
    assert resp.status_code == 200
    detail = resp.json()
    assert detail["id"] == "two-nets-9f01aa"
    assert detail["name"] == "Two Nets"
    assert len(detail["networks"]) == 2


def test_instantiate_preset_empty_body(monkeypatch):
    async def do_post(path, data=None):
        assert data == {}
        return {"topology": _saved_topology()}

    client = _client(monkeypatch, post=do_post)
    assert client.post("/api/presets/two-nets/instantiate").status_code == 200


def test_instantiate_preset_unknown_id(monkeypatch):
    from fastapi import HTTPException

    async def do_post(path, data=None):
        raise HTTPException(status_code=404, detail="Preset 'nope' not found.")

    client = _client(monkeypatch, post=do_post)
    resp = client.post("/api/presets/nope/instantiate", json={})
    assert resp.status_code == 404
