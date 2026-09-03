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
| `TOPOLOGY_PLUGIN_URL` | `http://scl-network-topology:9002` | Network topology plugin URL |
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
| POST | `/api/sessions` | Create a session with an initial goal |

## How It Works

1. The Network Topology plugin creates `topology.json` files under `data/topologies/<id>/`.
2. Each host in the topology may have an `agents` array, e.g. `["coder56"]`.
3. When a topology is started, the network-topology plugin builds containers using the `scl-plugin-network-topology-ubuntu-opencode` image for hosts with agents.
4. The Agent Manager discovers running containers, reads their topology file, and displays the configured agents.
5. The **Agents** page filters assignments so only agents from currently-running topologies are shown.
6. Creating a session calls the OpenCode HTTP API inside the container on port `4096`.

## Testing

Run the assignment verification test:

```bash
python tests/test_assignments.py
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
