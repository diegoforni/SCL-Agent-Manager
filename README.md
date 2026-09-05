# Agent Manager Plugin

## Overview

The Agent Manager plugin provides a web UI and REST API for managing AI agents inside StratoCyberLab network topologies. It discovers topology containers via Docker labels, reads agent assignments from topology files, and lets users start interactive sessions with OpenCode-enabled agents.

## Features

- **Container Discovery**: Discovers SCL topology containers by Docker labels (`scl.plugin=network-topology`).
- **Agent Display**: Shows only agents from topologies that currently have running containers.
- **Session Management**: Create sessions and send goals to agents running inside containers.
- **OpenCode Integration**: Health checks and session proxying for OpenCode servers on port `4096`.
- **State Tracking**: Reads agent assignments dynamically from each topology's `topology.json`.

## Architecture

```
agent-manager/
├── backend/                 # FastAPI/Quart Python backend
│   ├── app.py              # Main application, routers, background tasks
│   ├── models.py           # Pydantic models
│   └── routers/
│       ├── agents.py       # Agent templates, assignments, status
│       ├── containers.py   # Container discovery and detail endpoints
│       ├── sessions.py     # Session creation and messaging
│       ├── topologies.py   # Topology start/stop proxy
│       └── reconciliation.py # Reconciliation status
│   └── services/
│       ├── agent_lifecycle.py # Assignment state helpers
│       ├── docker_client.py   # Docker discovery, OpenCode readiness
│       ├── opencode_client.py # OpenCode session API client
│       └── topology_client.py # topology.json loader
├── frontend/               # React + TypeScript + Vite UI
│   └── src/pages/
│       ├── AgentsPage.tsx      # Agent goal/session UI
│       ├── HostDiscoveryPage.tsx # Container/agent assignment UI
│       └── TopologyPage.tsx    # Topology list
├── tests/                  # Test scripts
├── scripts/                # Build and utility scripts
├── Dockerfile.dashboard    # Multi-stage build for dashboard image
├── Dockerfile.opencode     # OpenCode image build
├── docker-compose.yml      # Production compose (port 9005)
├── .gitignore              # Python, Node, and runtime data exclusions
└── README.md
```

## Running

Run all commands from the repository root.

### With Docker Compose (recommended)

The Compose stack uses the external Docker network `playground-net`, which is created by the base StratoCyberLab stack. Start the base stack before starting this plugin.

```bash
# Set LLM environment variables (required for agent functionality)
export OPENCODE_API_KEY=your-api-key-here
export LLM_URL=https://llm.ai.e-infra.cz/v1
export LLM_MODEL=qwen3-coder
# Start the services
docker compose -f plugins/agent-manager/docker-compose.yml up -d --build
```

The dashboard is available at http://localhost:9005 (override the host port with `DASHBOARD_PORT`).
The image contains the backend and bundled topologies, so its production Compose
file does not bind-mount plugin source directories. This lets StratoCyberLab's
dashboard start the plugin through Docker Desktop on macOS.

## Configuration

Environment variables (set in `docker-compose.yml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `TOPOLOGY_DATA_DIR` | `/app/topologies/topologies` | Path to topology data inside the container |
| `AGENT_STATE_DIR` | `/app/state` | Path to agent state volume |
| `DASHBOARD_PORT` | `8080` | Internal backend port |
| `OUTPUTS_DIR` | `/outputs` | Trident/timeline output directory |
| `TOPOLOGY_PLUGIN_URL` | `http://scl-plugin-network-topology-control-plane:9002` | Network topology plugin URL |
| `LOG_LEVEL` | `INFO` | Logging level |

### LLM Configuration

For OpenCode agents to function, ensure the following environment variables are set when starting the topology plugin:

```bash
export OPENCODE_API_KEY=your-api-key-here
export LLM_URL=https://llm.ai.e-infra.cz/v1
export LLM_MODEL=qwen3-coder
```

**Important**: Never hardcode API keys in `.env` files. Always pass them via the shell environment.

## API Endpoints

### Agents

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agents/health` | Service health check |
| GET | `/api/agents/templates` | List supported agent templates |
| GET | `/api/agents/templates/{type}` | Get one template |
| GET | `/api/agents/assignments` | List assignments (optionally filter by `topology_id`) |
| GET | `/api/agents/state` | Get full agent state |
| GET | `/api/agents/status/{topology_id}/{host_id}` | Status for one host |
| POST | `/api/agents/assign` | Queue an agent assignment |
| DELETE | `/api/agents/{topology_id}/{host_id}/{agent_type}` | Remove an agent |

### Containers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/containers` | List containers (alias, enriched from topology) |
| GET | `/api/containers/discover` | Discover with filters |
| GET | `/api/containers/{container_id}` | Container details |
| GET | `/api/containers/by-host/{topology_id}/{host_id}` | Lookup by host |

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sessions/list` | List sessions |
| GET | `/api/sessions/{session_id}` | Get session info |
| GET | `/api/sessions/{session_id}/messages` | Get messages |
| GET | `/api/sessions/{session_id}/agents` | Agent sessions in this run (lead, subagents, guardrail) |
| GET | `/api/sessions/{session_id}/agents/{agent_session_id}/messages` | Messages of one agent in the run |
| POST | `/api/sessions` | Create a session with an initial goal |

## How It Works

1. The Network Topology plugin creates `topology.json` files under `data/topologies/<id>/`.
2. Each host in the topology may have an `agents` array, e.g. `["coder56"]`.
3. When a topology is started, the network-topology plugin builds containers using the `scl-plugin-network-topology-ubuntu-opencode` image for hosts with agents.
4. The Agent Manager discovers running containers, reads their topology file, and displays the configured agents.
5. The **Agents** page filters assignments so only agents from currently-running topologies are shown.
6. Creating a session calls the OpenCode HTTP API inside the container on port `4096`.

## Working With Agents

### Where agents live

Every agent runs inside the topology host container assigned to it (e.g. the
`atk_1` attacker box). The container is visible on the **Agents** page; the
container id shown there is the Docker container to use in every command below.

### Which IP does an agent's container have?

Topology containers attach to per-topology Docker networks, so each container
has one IP per attached network:

```bash
# All networks + IPs of one agent container
docker inspect <container> --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}: {{$v.IPAddress}}{{"\n"}}{{end}}'

# IPs of every running topology container
docker ps --filter label=scl.plugin=network-topology --format '{{.Names}}' | \
  xargs -I{} docker inspect {} --format '{}: {{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'
```

The Agent Manager backend reaches these IPs directly: on first contact it
attaches itself to the topology's network and then talks to the container's
OpenCode server on port `4096`. From the host you do not need the IP — use
`docker exec` (below).

### Seeing what the agents are doing

- **Agents page** — each panel is one deployed agent. For `coder56`, the chip
  strip above the message stream lists **every agent participating in the
  run**: the lead session, each `coder56_phase` / `coder56_verifier` subagent
  it spawned (they exist only inside OpenCode, as child sessions), and the
  `guardrail` judge session. Click a chip to pin one agent's stream; the
  default follows the most recently active agent automatically.
- **coder56 console** (port 9006, separate app) — per-run view with the live
  phase stream, guardrail verdict feed, and approvals.
- **Run artifacts** — everything an engagement produces lands on the host under
  `/outputs/<run_id>/` (phase reports, verifier `*.jsonl` verdicts, guardrail
  `verdicts.ndjson`, memory, and an `opencode.db` snapshot of the full agent
  transcripts at every phase boundary).
- **Raw logs**:
  ```bash
  docker logs -f <container>            # container / OpenCode server output
  docker exec <container> tail -50 /root/.local/share/opencode/log/*.log
  ```

### Talking to OpenCode directly

Each agent container runs an OpenCode HTTP server on port `4096` (localhost
inside the container). The dashboard is a thin proxy over it — you can drive
or inspect it yourself with `docker exec` + curl:

```bash
# Health
docker exec <container> curl -s http://localhost:4096/global/health

# All sessions in this container (children carry parentID = the lead session)
docker exec <container> curl -s http://localhost:4096/session | python3 -m json.tool

# One session's transcript
docker exec <container> curl -s http://localhost:4096/session/<session_id>/message | python3 -m json.tool

# Session busy/idle map
docker exec <container> curl -s http://localhost:4096/session/status

# Create a session
docker exec <container> curl -s -X POST http://localhost:4096/session \
  -H 'Content-Type: application/json' \
  -d '{"title": "manual steer"}'

# Send a prompt to a session (async fire-and-forget; use /message for sync)
docker exec <container> curl -s -X POST http://localhost:4096/session/<session_id>/prompt_async \
  -H 'Content-Type: application/json' \
  -d '{"parts": [{"type": "text", "text": "SUMMARY: what did you establish so far?"}]}'

# Abort a runaway session
docker exec <container> curl -s -X POST http://localhost:4096/session/<session_id>/abort
```

Prompt bodies use the `{"parts": [{"type": "text", "text": "..."}]}` shape and
accept an optional `"agent"` field (e.g. `"coder56"`) to select which baked-in
agent persona answers. Prefer the dashboard for anything the guardrail should
see — direct OpenCode prompts bypass the Agents-page goal forwarding that
keeps the coder56 guardrail's live goal file up to date.

## Testing

Run the assignment verification test:

```bash
python tests/test_assignments.py
```

Backend unit tests (no containers required):

```bash
python3 -m pytest backend/tests/ -q
```

## Troubleshooting

### Agents page shows "No agents are currently deployed"

1. Check that the target topology is running:
   ```bash
   curl 'http://localhost:9005/api/containers/discover?state=running'
   ```
2. Verify the topology host has an `agents` array in `topology.json`.
3. Check that `current_agents` is populated:
   ```bash
   curl 'http://localhost:9005/api/containers?topology_id=<id>'
   ```

### Session creation fails

1. Check OpenCode health inside the container:
   ```bash
   docker exec <container> curl -s http://localhost:4096/global/health
   ```
2. Verify `/root/.config/opencode/opencode.json` has:
   - `"$schema": "https://opencode.ai/config.json"`
   - `"baseURL": "{env:LLM_URL}"`
   - `"apiKey": "{env:OPENCODE_API_KEY}"`
3. Inspect OpenCode logs:
   ```bash
   docker exec <container> tail -50 /root/.local/share/opencode/log/*.log
   ```

## License

StratoCyberLab - Educational Cyber Range Platform
