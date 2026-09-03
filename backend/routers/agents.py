"""
Agents Router for Agent Manager Plugin

Implements all endpoints from the migration plan:
- GET /api/agents/templates - List available agent templates
- POST /api/agents/assign - Assign agent to host (with background recreation)
- DELETE /api/agents/{topology_id}/{host_id}/{agent_type} - Remove agent
- GET /api/agents/state - Get current agent state
- GET /api/agents/status/{topology_id}/{host_id} - Get agent status for host
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Path,
    Query,
    status
)
from pydantic import BaseModel, Field

from ..models import (
    AgentAssignment,
    AgentAssignmentResponse,
    AgentAssignmentState,
    AgentState,
    AgentStateAssignment,
    AgentTemplate,
    AgentTemplatesResponse,
    AgentType,
    APIResponse,
    ContainerInfo,
    ContainerState,
)
from ..services.agent_lifecycle import (
    assign_agent,
    remove_agent,
    load_agent_state,
    save_agent_state,
    get_agent_assignments,
    get_opencode_image,
    list_supported_agents,
)
from ..services.docker_client import (
    create_docker_client,
    list_containers,
    check_opencode_ready,
    get_container_by_host_id,
    ContainerRecreationError,
    DockerComposeError,
)
from ..services.topology_client import find_host
from ..services.state_manager import (
    get_state_manager,
    get_reconciliation_state,
)


logger = logging.getLogger(__name__)


# =============================================================================
# Router
# =============================================================================

router = APIRouter(
    prefix="/api/agents",
    tags=["agents"],
)


# =============================================================================
# Agent Templates
# =============================================================================

# Agent template definitions (could be loaded from config/database)
# Coder56 (red-team), DB_ADMIN (benign), and SOC_GOD (autonomous blue-team defender)
AGENT_TEMPLATES: Dict[AgentType, AgentTemplate] = {
    AgentType.CODER56: AgentTemplate(
        agent_type=AgentType.CODER56,
        name="Coder 5.6",
        description="Non-conversational, autonomous red-team subsystem for cyber security simulations. Performs reconnaissance, exploitation, and persistence operations.",
        capabilities=[
            {"name": "Network Reconnaissance", "description": "Discover active hosts, open ports, and services"},
            {"name": "Exploitation", "description": "Execute offensive security operations in simulated environments"},
            {"name": "Persistence", "description": "Maintain access and establish persistence mechanisms"},
            {"name": "Tool Installation", "description": "Install and configure security tools as needed"},
        ],
        opencode_image_required=True,
        supported_base_images=["ubuntu:24.04", "ubuntu:22.04", "debian:12"],
    ),
    AgentType.DB_ADMIN: AgentTemplate(
        agent_type=AgentType.DB_ADMIN,
        name="Database Administrator (Benign)",
        description="John Scott, a database administrator performing routine administrative tasks. Legitimate access to PostgreSQL infrastructure with normal human behavior patterns including breaks and web research.",
        capabilities=[
            {"name": "Database Administration", "description": "Perform routine DBA tasks and database operations"},
            {"name": "Query Operations", "description": "Execute SELECT, INSERT, UPDATE, DELETE operations"},
            {"name": "Web Research", "description": "Research database best practices before operations"},
            {"name": "Human Simulation", "description": "Exhibits natural human behavior including work breaks"},
        ],
        opencode_image_required=True,
        supported_base_images=["ubuntu:24.04", "ubuntu:22.04", "debian:12"],
    ),
    AgentType.SOC_GOD: AgentTemplate(
        agent_type=AgentType.SOC_GOD,
        name="SOC God (Autonomous Defender)",
        description="Autonomous blue-team defender. Analyzes IDS alerts and executes immediate remediation (firewall containment, process kills) plus creative deception/counter-attack, while preserving its own SSH/HTTPS/OpenCode connectivity.",
        capabilities=[
            {"name": "Threat Detection & Analysis", "description": "Ingest IDS alerts, classify threats and assess risk"},
            {"name": "Threat Containment", "description": "Apply firewall drops and process kills against attacker sources"},
            {"name": "Deception & Counter-attack", "description": "Deploy honeypots and active counter-measures after containment"},
        ],
        opencode_image_required=True,
        supported_base_images=["ubuntu:24.04", "ubuntu:22.04", "debian:12"],
    ),
}


@router.get(
    "/templates",
    response_model=AgentTemplatesResponse,
    summary="Get Agent Templates",
    description="Retrieve all available agent templates with capabilities and requirements."
)
async def get_agent_templates() -> AgentTemplatesResponse:
    """
    Get all available agent templates.

    Returns:
        AgentTemplatesResponse containing all agent templates
    """
    return AgentTemplatesResponse(agents=AGENT_TEMPLATES)


@router.get(
    "/templates/{agent_type}",
    response_model=AgentTemplate,
    summary="Get Agent Template",
    description="Retrieve a specific agent template by type."
)
async def get_agent_template(
    agent_type: AgentType = Path(..., description="Agent type to retrieve")
) -> AgentTemplate:
    """
    Get a specific agent template.

    Args:
        agent_type: The agent type to retrieve

    Returns:
        AgentTemplate for the requested type

    Raises:
        HTTPException: If agent type not found
    """
    if agent_type not in AGENT_TEMPLATES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent type '{agent_type}' not found"
        )
    return AGENT_TEMPLATES[agent_type]


# =============================================================================
# Agent Assignment
# =============================================================================

class BackgroundJobTracker:
    """Simple in-memory tracker for background jobs."""

    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}

    def add_job(self, job_id: str, job_type: str, details: Dict[str, Any]) -> None:
        """Add a new job to track."""
        self.jobs[job_id] = {
            "job_id": job_id,
            "job_type": job_type,
            "status": "queued",
            "created_at": datetime.utcnow().isoformat(),
            **details
        }

    def update_job(self, job_id: str, updates: Dict[str, Any]) -> None:
        """Update job status."""
        if job_id in self.jobs:
            self.jobs[job_id].update(updates)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job details."""
        return self.jobs.get(job_id)


# Global job tracker instance
_job_tracker = BackgroundJobTracker()


async def run_agent_assignment(
    assignment: AgentAssignment,
    job_id: str
) -> None:
    """
    Background task to complete agent assignment with container recreation.

    Args:
        assignment: Agent assignment request
        job_id: Job ID for tracking
    """
    try:
        logger.info(f"Starting background agent assignment {job_id}")
        _job_tracker.update_job(job_id, {"status": "running"})

        # Execute the full assignment flow
        result = await assign_agent(assignment)

        # Update job tracker with result.
        # READY, ASSIGNED and REMOVED are terminal success states; only FAILED
        # is treated as an error.
        successful_states = {
            AgentAssignmentState.READY,
            AgentAssignmentState.ASSIGNED,
        }
        _job_tracker.update_job(job_id, {
            "status": "completed" if result.status in successful_states else "failed",
            "result": result.dict(),
            "completed_at": datetime.utcnow().isoformat()
        })

        logger.info(f"Completed background agent assignment {job_id}: {result.status}")

    except Exception as e:
        logger.error(f"Background agent assignment {job_id} failed: {e}", exc_info=True)
        _job_tracker.update_job(job_id, {
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.utcnow().isoformat()
        })


@router.post(
    "/assign",
    response_model=AgentAssignmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Assign Agent to Host",
    description="Assign an agent to a host. Returns immediately with job ID, runs recreation in background."
)
async def assign_agent_endpoint(
    assignment: AgentAssignment,
    background_tasks: BackgroundTasks
) -> AgentAssignmentResponse:
    """
    Assign an agent to a host with background container recreation.

    This endpoint triggers the Container Recreation Approach:
    1. Returns immediately with job_id and status=PENDING
    2. Background task completes the assignment:
       - Adds agent to topology
       - Regenerates docker-compose
       - Recreates container
       - Waits for OpenCode readiness
       - Updates agent state

    Args:
        assignment: Agent assignment request
        background_tasks: FastAPI BackgroundTasks for async execution

    Returns:
        AgentAssignmentResponse with job_id and PENDING status
    """
    job_id = str(uuid.uuid4())

    # Add to job tracker
    _job_tracker.add_job(
        job_id,
        "agent_assign",
        {
            "topology_id": assignment.topology_id,
            "network_id": assignment.network_id,
            "host_id": assignment.host_id,
            "agent_type": assignment.agent_type.value,
        }
    )

    # Queue background task
    background_tasks.add_task(run_agent_assignment, assignment, job_id)

    logger.info(f"Queued agent assignment job {job_id}: {assignment.agent_type} -> {assignment.host_id}")

    return AgentAssignmentResponse(
        status=AgentAssignmentState.PENDING,
        message="Agent assignment queued for background processing",
        topology_id=assignment.topology_id,
        network_id=assignment.network_id,
        host_id=assignment.host_id,
        agent_type=assignment.agent_type,
        job_id=job_id,
        estimated_completion_seconds=30
    )


# =============================================================================
# Agent Removal
# =============================================================================

async def run_agent_removal(
    topology_id: str,
    network_id: str,
    host_id: str,
    agent_type: AgentType,
    job_id: str
) -> None:
    """
    Background task to remove agent from host with container recreation.

    Args:
        topology_id: Topology identifier
        network_id: Network identifier
        host_id: Host identifier
        agent_type: Agent type to remove
        job_id: Job ID for tracking
    """
    try:
        logger.info(f"Starting background agent removal {job_id}")
        _job_tracker.update_job(job_id, {"status": "running"})

        # Execute the removal flow
        result = await remove_agent(
            topology_id=topology_id,
            network_id=network_id,
            host_id=host_id,
            agent_type=agent_type
        )

        # Update job tracker with result. REMOVED is a terminal success state.
        _job_tracker.update_job(job_id, {
            "status": "completed" if result.status == AgentAssignmentState.REMOVED else "failed",
            "result": result.dict(),
            "completed_at": datetime.utcnow().isoformat()
        })

        logger.info(f"Completed background agent removal {job_id}: {result.status}")

    except Exception as e:
        logger.error(f"Background agent removal {job_id} failed: {e}", exc_info=True)
        _job_tracker.update_job(job_id, {
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.utcnow().isoformat()
        })


@router.delete(
    "/{topology_id}/{host_id}/{agent_type}",
    response_model=AgentAssignmentResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Remove Agent from Host",
    description="Remove an agent from a host. Returns immediately with job ID, runs recreation in background."
)
async def remove_agent_endpoint(
    background_tasks: BackgroundTasks,
    topology_id: str = Path(..., description="Topology identifier"),
    host_id: str = Path(..., description="Host identifier"),
    agent_type: AgentType = Path(..., description="Agent type to remove"),
    network_id: str = Query(..., description="Network identifier")
) -> AgentAssignmentResponse:
    """
    Remove an agent from a host with background container recreation.

    This endpoint triggers the removal flow:
    1. Returns immediately with job_id and status=PENDING
    2. Background task completes the removal:
       - Removes agent from topology
       - Regenerates docker-compose
       - Recreates container (with original image)
       - Updates agent state

    Args:
        topology_id: Topology identifier
        host_id: Host identifier
        agent_type: Agent type to remove
        network_id: Network identifier
        background_tasks: FastAPI BackgroundTasks

    Returns:
        AgentAssignmentResponse with job_id and PENDING status
    """
    job_id = str(uuid.uuid4())

    # Add to job tracker
    _job_tracker.add_job(
        job_id,
        "agent_remove",
        {
            "topology_id": topology_id,
            "network_id": network_id,
            "host_id": host_id,
            "agent_type": agent_type.value,
        }
    )

    # Queue background task
    background_tasks.add_task(
        run_agent_removal,
        topology_id,
        network_id,
        host_id,
        agent_type,
        job_id
    )

    logger.info(f"Queued agent removal job {job_id}: {agent_type} from {host_id}")

    return AgentAssignmentResponse(
        status=AgentAssignmentState.PENDING,
        message="Agent removal queued for background processing",
        topology_id=topology_id,
        network_id=network_id,
        host_id=host_id,
        agent_type=agent_type,
        job_id=job_id,
        estimated_completion_seconds=30
    )


# =============================================================================
# Agent State
# =============================================================================

@router.get(
    "/state",
    response_model=AgentState,
    summary="Get Agent State",
    description="Retrieve the current global agent state with all assignments."
)
async def get_agent_state_endpoint(
    state_path: Optional[str] = Query(None, description="Optional path to agent state file")
) -> AgentState:
    """
    Get the current agent state.

    Returns the global agent state including all active assignments
    and sessions.

    Args:
        state_path: Optional path to agent state file

    Returns:
        Current AgentState
    """
    try:
        # Derived from topology.json (single source of truth) — no persisted registry.
        return AgentState(assignments=get_agent_assignments())
    except Exception as e:
        logger.error(f"Failed to load agent state: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load agent state: {str(e)}"
        )


@router.get(
    "/assignments",
    response_model=List[AgentStateAssignment],
    summary="Get Agent Assignments",
    description="Retrieve all current agent assignments, optionally filtered."
)
async def get_assignments_endpoint(
    topology_id: Optional[str] = Query(None, description="Filter by topology ID"),
    host_id: Optional[str] = Query(None, description="Filter by host ID"),
    state_path: Optional[str] = Query(None, description="Optional path to agent state file")
) -> List[AgentStateAssignment]:
    """
    Get current agent assignments.

    Args:
        topology_id: Optional filter by topology
        host_id: Optional filter by host
        state_path: Optional path to agent state file

    Returns:
        List of matching agent assignments
    """
    try:
        from ..services.agent_lifecycle import get_agent_assignments_async
        return await get_agent_assignments_async(topology_id, host_id, state_path)
    except Exception as e:
        logger.error(f"Failed to get assignments: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get assignments: {str(e)}"
        )


# =============================================================================
# Agent Status for Host
# =============================================================================

class AgentHostStatus(BaseModel):
    """Status of agents on a specific host."""
    topology_id: str = Field(..., description="Topology ID")
    network_id: str = Field(..., description="Network ID")
    host_id: str = Field(..., description="Host ID")
    host_name: str = Field(..., description="Host name")
    container_id: Optional[str] = Field(None, description="Container ID if running")
    container_name: Optional[str] = Field(None, description="Container name")
    container_state: Optional[ContainerState] = Field(None, description="Container state")
    assigned_agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents assigned to this host"
    )
    opencode_ready: bool = Field(
        default=False,
        description="Whether OpenCode is ready for agents"
    )
    last_updated: datetime = Field(
        default_factory=datetime.utcnow,
        description="Last update timestamp"
    )


@router.get(
    "/status/{topology_id}/{host_id}",
    response_model=AgentHostStatus,
    summary="Get Agent Status for Host",
    description="Get the current agent status and container state for a specific host."
)
async def get_host_status_endpoint(
    topology_id: str = Path(..., description="Topology identifier"),
    host_id: str = Path(..., description="Host identifier"),
    network_id: str = Query(..., description="Network identifier")
) -> AgentHostStatus:
    """
    Get the agent status for a specific host.

    This endpoint provides a comprehensive view of:
    - Container state (if running)
    - Currently assigned agents
    - OpenCode readiness status

    Args:
        topology_id: Topology identifier
        host_id: Host identifier
        network_id: Network identifier

    Returns:
        AgentHostStatus with current status

    Raises:
        HTTPException: If host not found or status cannot be determined
    """
    try:
        # Get agent assignments for this host
        assignments = get_agent_assignments(topology_id, host_id)
        assigned_agents = [a.agent_type for a in assignments]

        # Try to get container info
        container_id = None
        container_name = None
        container_state = None
        opencode_ready = False
        host_name = host_id

        async with create_docker_client() as docker:
            containers = await list_containers(
                docker,
                topology_id=topology_id,
                host_id=host_id
            )

            if containers:
                container = containers[0]
                container_id = container.container_id
                container_name = container.container_name
                container_state = ContainerState(container.state.value)
                host_name = container.host_name or host_id
                opencode_ready = await check_opencode_ready(docker, container_id)

        # Fallback to topology for host_name if still empty
        if not host_name or host_name == host_id:
            try:
                host_data = find_host(topology_id, host_id)
                if host_data:
                    host_name = host_data.get("name") or host_id
            except Exception:
                pass

        return AgentHostStatus(
            topology_id=topology_id,
            network_id=network_id,
            host_id=host_id,
            host_name=host_name,
            container_id=container_id,
            container_name=container_name,
            container_state=container_state,
            assigned_agents=assigned_agents,
            opencode_ready=opencode_ready
        )

    except Exception as e:
        logger.error(f"Failed to get host status: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get host status: {str(e)}"
        )


# =============================================================================
# Job Status
# =============================================================================

class JobStatusResponse(BaseModel):
    """Response for job status queries."""
    job_id: str = Field(..., description="Job identifier")
    job_type: str = Field(..., description="Type of job (agent_assign, agent_remove)")
    status: str = Field(..., description="Job status (queued, running, completed, failed)")
    created_at: datetime = Field(..., description="Job creation time")
    completed_at: Optional[datetime] = Field(None, description="Job completion time")
    result: Optional[Dict[str, Any]] = Field(None, description="Job result if completed")
    error: Optional[str] = Field(None, description="Error message if failed")


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    summary="Get Job Status",
    description="Check the status of a background agent assignment/removal job."
)
async def get_job_status(
    job_id: str = Path(..., description="Job ID to check")
) -> JobStatusResponse:
    """
    Get the status of a background job.

    Args:
        job_id: Job identifier from assignment or removal response

    Returns:
        JobStatusResponse with current status

    Raises:
        HTTPException: If job not found
    """
    job = _job_tracker.get_job(job_id)

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found"
        )

    return JobStatusResponse(**job)


# =============================================================================
# Container Discovery
# =============================================================================

@router.get(
    "/containers",
    response_model=List[ContainerInfo],
    summary="Discover Containers",
    description="Discover all SCL topology containers with optional filters."
)
async def discover_containers(
    topology_id: Optional[str] = Query(None, description="Filter by topology ID"),
    host_id: Optional[str] = Query(None, description="Filter by host ID"),
    state: Optional[ContainerState] = Query(None, description="Filter by container state"),
    has_agents: Optional[bool] = Query(None, description="Filter by agent assignment")
) -> List[ContainerInfo]:
    """
    Discover SCL topology containers.

    Args:
        topology_id: Optional filter by topology
        host_id: Optional filter by host
        state: Optional filter by container state
        has_agents: Optional filter by agent assignment

    Returns:
        List of discovered container info
    """
    try:
        async with create_docker_client() as docker:
            containers = await list_containers(
                docker,
                topology_id=topology_id,
                host_id=host_id,
                state=state,
                has_agents=has_agents
            )

            # Convert dataclass to pydantic model for response
            return [
                ContainerInfo(
                    container_id=c.container_id,
                    container_name=c.container_name,
                    topology_id=c.topology_id,
                    network_id=c.network_id,
                    host_id=c.host_id,
                    host_name=c.host_name,
                    host_type=c.host_type,
                    ip_address=c.ip_address,
                    image=c.image,
                    state=c.state,
                    current_agents=c.current_agents,
                    can_assign_agent=c.can_assign_agent,
                    opencode_ready=c.opencode_ready,
                    opencode_port=c.opencode_port,
                    labels=c.labels
                )
                for c in containers
            ]

    except Exception as e:
        logger.error(f"Container discovery failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Container discovery failed: {str(e)}"
        )


# =============================================================================
# Health/Validation Endpoints
# =============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    supported_agents: List[str] = Field(..., description="Supported agent types")


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Check service health and list supported agent types."
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Returns:
        HealthResponse with service status and capabilities
    """
    return HealthResponse(
        status="healthy",
        version="1.0.1",
        supported_agents=[agent.value for agent in list_supported_agents()]
    )


class ValidationResponse(BaseModel):
    """Validation response for agent assignment."""
    valid: bool = Field(..., description="Whether assignment is valid")
    message: str = Field(..., description="Validation message")
    warnings: List[str] = Field(default_factory=list, description="Validation warnings")


@router.post(
    "/validate",
    response_model=ValidationResponse,
    summary="Validate Agent Assignment",
    description="Validate if an agent assignment is possible before attempting."
)
async def validate_assignment(
    assignment: AgentAssignment
) -> ValidationResponse:
    """
    Validate an agent assignment request.

    Checks:
    - Host exists in topology
    - Host type supports the agent type
    - Agent not already assigned (warning)

    Args:
        assignment: Agent assignment to validate

    Returns:
        ValidationResponse with validation result
    """
    from ..services.agent_lifecycle import validate_agent_assignment

    try:
        validation = validate_agent_assignment(
            topology_id=assignment.topology_id,
            network_id=assignment.network_id,
            host_id=assignment.host_id,
            agent_type=assignment.agent_type
        )

        return ValidationResponse(
            valid=validation['valid'],
            message=validation['message'],
            warnings=[validation.get('warning')] if validation.get('warning') else []
        )

    except Exception as e:
        logger.error(f"Validation failed: {e}", exc_info=True)
        return ValidationResponse(
            valid=False,
            message=f"Validation error: {str(e)}",
            warnings=[]
        )


# =============================================================================
# Reconciliation Endpoints
# =============================================================================

class ReconciliationStatusResponse(BaseModel):
    """Current reconciliation status."""
    last_reconciliation_at: Optional[datetime] = Field(None, description="Last reconciliation time")
    auto_reconcile_enabled: bool = Field(False, description="Auto-reconcile status")
    reconcile_interval_seconds: int = Field(300, description="Reconcile interval")
    sync_status: str = Field(..., description="Current sync status")
    pending_operations: int = Field(0, description="Pending operations count")


@router.get(
    "/reconciliation/status",
    response_model=ReconciliationStatusResponse,
    summary="Get Reconciliation Status",
    description="Get the current state reconciliation status."
)
async def get_reconciliation_status_endpoint() -> ReconciliationStatusResponse:
    """
    Get reconciliation status.

    Returns the current state of reconciliation operations and
    any pending state fixes.

    Returns:
        ReconciliationStatusResponse with current status
    """
    try:
        state = get_reconciliation_state()

        return ReconciliationStatusResponse(
            last_reconciliation_at=None,
            auto_reconcile_enabled=False,
            reconcile_interval_seconds=300,
            sync_status=state.get('sync_status', 'idle'),
            pending_operations=len(state.get('pending_operations', []))
        )

    except Exception as e:
        logger.error(f"Failed to get reconciliation status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get reconciliation status: {str(e)}"
        )
