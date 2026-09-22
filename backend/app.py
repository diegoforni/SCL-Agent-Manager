"""
Agent Manager FastAPI Application

Main application entry point for the Agent Manager Plugin.
Provides REST API and WebSocket endpoints for agent lifecycle management,
container operations, session handling, and state reconciliation.
"""

import asyncio
import faulthandler
import logging
import os
import signal
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .models import (
    APIResponse,
    HealthResponse,
    MetricsResponse,
    ComponentHealth,
    AgentMetrics,
    ContainerMetrics,
    ContainerState,
    SessionMetrics,
    WebSocketMetrics,
    BackgroundTaskMetrics,
)
from .services import (
    # State management
    get_state_manager,

    # Docker operations
    create_docker_client,
    list_containers,

    # Agent lifecycle
    get_agent_state,
    get_agent_assignments,

    # OpenCode client
    check_opencode_ready_async,
)
from .routers.reconciliation import get_reconciliation_service


# =============================================================================
# Configuration
# =============================================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Dump all thread stacks on SIGUSR1 so a wedged event loop can be diagnosed
# from outside the container (docker kill -s USR1 <container>). Works even when
# the loop is fully blocked — faulthandler runs on a dedicated thread.
try:
    faulthandler.register(signal.SIGUSR1, all_threads=True, chain=False)
except (ValueError, OSError):  # not main thread / unsupported platform
    pass
RECONCILE_INTERVAL_SECONDS = int(os.getenv("RECONCILE_INTERVAL_SECONDS", "300"))  # 5 minutes
IMAGE_BUILD_INTERVAL_SECONDS = int(os.getenv("IMAGE_BUILD_INTERVAL_SECONDS", "3600"))  # 1 hour
# The defender auto_responder is a no-op when no topology has the defender enabled,
# but can be disabled entirely with DEFENDER_AUTORESPONDER_ENABLED=false.
DEFENDER_AUTORESPONDER_ENABLED = os.getenv("DEFENDER_AUTORESPONDER_ENABLED", "true").lower() in ("1", "true", "yes")


# =============================================================================
# Logging Setup
# =============================================================================

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# WebSocket Connection Manager
# =============================================================================

class ConnectionManager:
    """Manages WebSocket connections for event streaming."""

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        """Accept and track a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a message to all connected clients."""
        if self.active_connections:
            logger.debug(f"Broadcasting event to {len(self.active_connections)} clients")
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error sending to WebSocket: {e}")
                    self.disconnect(connection)

    async def send_personal(self, message: Dict[str, Any], websocket: WebSocket):
        """Send a message to a specific WebSocket client."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
            self.disconnect(websocket)


# Global connection manager
connection_manager = ConnectionManager()


# =============================================================================
# Background Tasks
# =============================================================================

class BackgroundTaskManager:
    """Manages periodic background tasks for reconciliation and image building."""

    def __init__(self):
        self.reconcile_task: Optional[asyncio.Task] = None
        self.image_build_task: Optional[asyncio.Task] = None
        self.defender_task: Optional[asyncio.Task] = None
        self._auto_responder = None
        self.running = False

    async def start(self):
        """Start all background tasks."""
        if self.running:
            logger.warning("Background tasks already running")
            return

        self.running = True
        logger.info("Starting background tasks...")

        # Start periodic reconciliation
        self.reconcile_task = asyncio.create_task(
            self._periodic_reconcile()
        )

        # Start periodic image building (placeholder)
        self.image_build_task = asyncio.create_task(
            self._periodic_image_build()
        )

        # Start the defender auto_responder (soc_god driver). It broadcasts
        # defender events over the existing WebSocket event stream.
        if DEFENDER_AUTORESPONDER_ENABLED:
            try:
                from .services.defender.auto_responder import AutoResponder
                self._auto_responder = AutoResponder(broadcast=connection_manager.broadcast)
                self.defender_task = asyncio.create_task(self._auto_responder.run())
                logger.info("Defender auto_responder started")
            except Exception as e:
                logger.error(f"Failed to start defender auto_responder: {e}", exc_info=True)

    async def stop(self):
        """Stop all background tasks."""
        if not self.running:
            return

        logger.info("Stopping background tasks...")
        self.running = False

        # Cancel tasks
        if self.reconcile_task:
            self.reconcile_task.cancel()
        if self.image_build_task:
            self.image_build_task.cancel()
        if self._auto_responder:
            self._auto_responder.stop()
        if self.defender_task:
            self.defender_task.cancel()

        # Wait for cancellation
        await asyncio.gather(
            self.reconcile_task if self.reconcile_task else asyncio.sleep(0),
            self.image_build_task if self.image_build_task else asyncio.sleep(0),
            self.defender_task if self.defender_task else asyncio.sleep(0),
            return_exceptions=True
        )

        logger.info("Background tasks stopped")

    async def _periodic_reconcile(self):
        """Periodically reconcile agent state with running containers."""
        logger.info(f"Starting periodic reconciliation (interval: {RECONCILE_INTERVAL_SECONDS}s)")

        service = get_reconciliation_service()
        try:
            await service.periodic_reconciliation(
                interval_seconds=RECONCILE_INTERVAL_SECONDS,
                enabled=True
            )
        except asyncio.CancelledError:
            logger.info("Reconciliation task cancelled")
        except Exception as e:
            logger.error(f"Error in periodic reconciliation: {e}", exc_info=True)

    async def _periodic_image_build(self):
        """Periodically check and build OpenCode images."""
        logger.info(f"Starting periodic image build checker (interval: {IMAGE_BUILD_INTERVAL_SECONDS}s)")

        while self.running:
            try:
                await asyncio.sleep(IMAGE_BUILD_INTERVAL_SECONDS)

                if not self.running:
                    break

                logger.info("Running periodic image build check...")

                # Broadcast image build start event
                await connection_manager.broadcast({
                    "type": "image_build_check_started",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {}
                })

                # TODO: Implement actual image build logic
                # This would check for missing or outdated images and build them

                await connection_manager.broadcast({
                    "type": "image_build_check_completed",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"status": "completed", "images_checked": []}
                })

            except asyncio.CancelledError:
                logger.info("Image build task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in periodic image build: {e}", exc_info=True)


# Global background task manager
background_tasks = BackgroundTaskManager()


# =============================================================================
# Lifespan Context Manager
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown events."""
    # Startup
    logger.info("Agent Manager starting up...")

    try:
        # Initialize state manager
        state_manager = get_state_manager()
        logger.info("State manager initialized")

        # Start background tasks
        await background_tasks.start()

        # REC #17: sweep every existing engagement and close the reportwriter gap
        # (reportwriter_input.json present but no report.json/report.html) left by
        # prior backend sessions, and advance status out of planning where
        # findings exist. Best-effort; never blocks startup on a report failure.
        try:
            from .routers.coder56 import _reconcile_all_engagement_reports
            # Run as a background task: full per-engagement LLM report generation
            # can take minutes and was blocking the lifespan, so uvicorn never
            # bound 8080 (HTTP 000). Sweep is best-effort; it must not gate startup.
            asyncio.create_task(_reconcile_all_engagement_reports())
            logger.info("Engagement reportwriter reconcile sweep scheduled (background)")
        except Exception as e:
            logger.warning(f"Engagement reportwriter reconcile sweep skipped: {e}")

        logger.info("Agent Manager startup complete")

    except Exception as e:
        logger.error(f"Error during startup: {e}", exc_info=True)
        raise

    yield

    # Shutdown
    logger.info("Agent Manager shutting down...")

    try:
        # Stop background tasks
        await background_tasks.stop()

        # Close state manager connections
        state_manager = get_state_manager()
        if hasattr(state_manager, 'close'):
            await state_manager.close()

        logger.info("Agent Manager shutdown complete")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)


# =============================================================================
# FastAPI Application
# =============================================================================

app = FastAPI(
    title="Agent Manager API",
    description="REST API for managing agent assignments, containers, and sessions in StratocyberLab",
    version="1.0.2",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)


# =============================================================================
# CORS Middleware
# =============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development flexibility
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Include Routers
# =============================================================================

from .routers import agents, containers, sessions, reconciliation, topologies, opencode_compat, timeline_compat, replay, settings, coder56, presets, guardrail_jev, guardrail_semif

# Routers already have prefixes defined, include without additional prefixes
app.include_router(agents.router)
app.include_router(containers.router)
app.include_router(sessions.router)
app.include_router(reconciliation.router)
app.include_router(topologies.router)
# Starter topology presets (plugin presets/ catalogue → instantiate)
app.include_router(presets.router)
# Add OpenCode compatibility router for Trident-style file-backed state
app.include_router(opencode_compat.router)
# Add Timeline compatibility router for Trident-style agent timeline data
app.include_router(timeline_compat.router)
# Add Replay router for historical run playback (select a past run, replay as if live)
app.include_router(replay.router)
# Add Settings router for LLM credentials management
app.include_router(settings.router)
# Coder56 Pentest Console: HITL guardrail + goal builder (standalone frontend)
app.include_router(coder56.router)
# Jev inline guardrail: orchestration-level prompt-injection classifier (OpenRouter)
app.include_router(guardrail_jev.router)
# SemIf inline guardrail: local open-source (Jev-pattern) prompt-injection classifier
app.include_router(guardrail_semif.router)

# Defender (soc_god) routers: alert ingest, enable/status, planner
from .services.defender import defender_router, planner_router
app.include_router(defender_router.router)
app.include_router(planner_router.router)


# =============================================================================
# WebSocket Events Endpoint (must be before static files)
# =============================================================================

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """
    WebSocket endpoint for real-time event streaming.

    Connected clients receive events for:
    - Agent assignment status changes
    - Container state changes
    - Session lifecycle events
    - Reconciliation progress
    - Image build status

    Clients can send commands:
    - {"type": "subscribe", "events": ["agent_assignments", "containers"]}
    - {"type": "ping"}
    """
    await connection_manager.connect(websocket)

    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()

            message_type = data.get("type")

            if message_type == "subscribe":
                # Client wants to subscribe to specific events
                # For now, we broadcast all events to all clients
                await connection_manager.send_personal({
                    "type": "subscribed",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {"events": data.get("events", ["*"])}
                }, websocket)

            elif message_type == "ping":
                # Respond to ping with pong
                await connection_manager.send_personal({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {}
                }, websocket)

            else:
                logger.warning(f"Unknown WebSocket message type: {message_type}")

    except WebSocketDisconnect:
        connection_manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")

    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        connection_manager.disconnect(websocket)


# =============================================================================
# Health Check Endpoint
# =============================================================================

@app.get("/health", response_model=HealthResponse, tags=["health"])
async def health_check():
    """
    Health check endpoint for monitoring and load balancers.

    Returns overall system health and component status.
    """
    overall_status = "healthy"
    components: Dict[str, ComponentHealth] = {}

    # Check OpenCode availability on running topology containers
    try:
        docker_client = create_docker_client()
        await docker_client.connect()
        try:
            from .services.docker_client import list_containers, check_opencode_ready
            containers = await list_containers(docker_client, state=ContainerState.RUNNING)
            opencode_ready = False
            for container in containers:
                if await check_opencode_ready(docker_client, container.container_id):
                    opencode_ready = True
                    break
            components["opencode"] = ComponentHealth(
                status="healthy" if opencode_ready else "degraded",
                ready=opencode_ready,
                container_count=len(containers)
            )
            if not opencode_ready:
                overall_status = "degraded"
        finally:
            await docker_client.close()
    except Exception as e:
        components["opencode"] = ComponentHealth(
            status="unhealthy",
            error=str(e)
        )
        overall_status = "degraded"

    # Check Docker availability
    try:
        docker_client = create_docker_client()
        await docker_client.connect()
        try:
            containers = await list_containers(docker_client)
            components["docker"] = ComponentHealth(
                status="healthy",
                container_count=len(containers)
            )
        finally:
            await docker_client.close()
    except Exception as e:
        components["docker"] = ComponentHealth(
            status="unhealthy",
            error=str(e)
        )
        overall_status = "degraded"

    # Check State Manager
    try:
        state_manager = get_state_manager()
        assignments = state_manager.get_all_assignments()
        components["state_manager"] = ComponentHealth(
            status="healthy",
            assignment_count=len(assignments)
        )
    except Exception as e:
        components["state_manager"] = ComponentHealth(
            status="unhealthy",
            error=str(e)
        )
        overall_status = "degraded"

    # Check WebSocket connections
    components["websocket"] = ComponentHealth(
        status="healthy",
        active_connections=len(connection_manager.active_connections)
    )

    return HealthResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        components=components
    )


# =============================================================================
# Metrics Endpoint
# =============================================================================

@app.get("/metrics", response_model=MetricsResponse, tags=["metrics"])
async def get_metrics():
    """
    Metrics endpoint for monitoring and observability.

    Returns current system metrics including:
    - Agent assignment counts by type and status
    - Container counts by state
    - Session counts by status
    - WebSocket connection counts
    - Background task status
    """
    state_manager = get_state_manager()
    docker_client = create_docker_client()

    # Agent metrics
    agent_metrics = AgentMetrics()
    try:
        agent_state = await get_agent_state(state_manager)
        assignments = agent_state.get("assignments", {})

        # Count by topology
        topology_counts: Dict[str, int] = {}
        for key in assignments.keys():
            topology_id = key.split(":")[0] if ":" in key else "unknown"
            topology_counts[topology_id] = topology_counts.get(topology_id, 0) + 1

        # Count by agent type
        type_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}

        for assignment in assignments.values():
            agent_type = assignment.get("agent_type", "unknown")
            assignment_status = assignment.get("status", "unknown")

            type_counts[agent_type] = type_counts.get(agent_type, 0) + 1
            status_counts[assignment_status] = status_counts.get(assignment_status, 0) + 1

        agent_metrics = AgentMetrics(
            total_assignments=len(assignments),
            by_topology=topology_counts,
            by_type=type_counts,
            by_status=status_counts
        )
    except Exception as e:
        logger.error(f"Error collecting agent metrics: {e}")

    # Container metrics
    container_metrics = ContainerMetrics()
    try:
        containers = await list_containers(docker_client)
        state_counts: Dict[str, int] = {}

        for container in containers:
            container_state = container.state.value
            state_counts[container_state] = state_counts.get(container_state, 0) + 1

        container_metrics = ContainerMetrics(
            total=len(containers),
            by_state=state_counts
        )
    except Exception as e:
        logger.error(f"Error collecting container metrics: {e}")

    # Session metrics (placeholder)
    session_metrics = SessionMetrics()

    # WebSocket metrics
    websocket_metrics = WebSocketMetrics(
        active_connections=len(connection_manager.active_connections)
    )

    # Background task metrics
    background_task_metrics = BackgroundTaskMetrics(
        reconcile_running=background_tasks.reconcile_task is not None and not background_tasks.reconcile_task.done(),
        image_build_running=background_tasks.image_build_task is not None and not background_tasks.image_build_task.done(),
        reconcile_interval_seconds=RECONCILE_INTERVAL_SECONDS,
        image_build_interval_seconds=IMAGE_BUILD_INTERVAL_SECONDS
    )

    return MetricsResponse(
        timestamp=datetime.utcnow(),
        agents=agent_metrics,
        containers=container_metrics,
        sessions=session_metrics,
        websocket=websocket_metrics,
        background_tasks=background_task_metrics
    )


# =============================================================================
# Static Files (must be after WebSocket routes and API endpoints)
# =============================================================================

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Mount frontend static files
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
index_path = os.path.join(frontend_path, "index.html")

if os.path.exists(frontend_path):
    # Serve static assets
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_path, "assets")), name="assets")

    # SPA fallback - serve index.html for all non-API routes
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve the SPA for all non-API, non-WebSocket routes."""
        # Skip API routes and WebSocket routes
        if full_path.startswith("api/") or full_path.startswith("ws/") or full_path.startswith("openapi.json") or full_path.startswith("docs") or full_path.startswith("redoc"):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=404,
                content={"detail": "Not Found"}
            )

        # Serve index.html for SPA client-side routing
        if os.path.exists(index_path):
            return FileResponse(index_path)
        else:
            logging.error(f"index.html not found at {index_path}")
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=503,
                content={"detail": "Frontend not available"}
            )

    # Also serve the root path
    @app.get("/")
    async def root():
        """Serve the SPA at root."""
        if os.path.exists(index_path):
            return FileResponse(index_path)
        else:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=503,
                content={"detail": "Frontend not available"}
            )
else:
    logging.warning(f"Frontend static files not found at {frontend_path}")


# =============================================================================
# Static Files (must be after WebSocket routes and API endpoints)
# =============================================================================

# Mount frontend static files
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
else:
    logging.warning(f"Frontend static files not found at {frontend_path}")


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
            "data": None
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler for unexpected errors."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "message": "Internal server error",
            "data": {"error": str(exc)}
        }
    )


# =============================================================================
# Main Entry Point (for development)
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=LOG_LEVEL.lower()
    )
