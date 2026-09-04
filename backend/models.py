"""
Pydantic models for Agent Manager Plugin.

Based on the Migration Plan for Topology and Agent Dashboard Plugins.
Defines models for agent assignment, container discovery, session management,
and state reconciliation.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Literal
from enum import Enum
from pydantic import BaseModel, Field, HttpUrl, validator


# =============================================================================
# Enums
# =============================================================================

class AgentType(str, Enum):
    """Supported agent types available for assignment."""
    CODER56 = "coder56"
    DB_ADMIN = "db_admin"
    SOC_GOD = "soc_god"


class HostType(str, Enum):
    """Host types that can be created in topologies."""
    WEB_SERVER = "web-server"
    DATABASE_SERVER = "database-server"
    WORKSTATION = "workstation"
    FIREWALL = "firewall"
    ROUTER = "router"
    SERVER = "server"
    DOMAIN_ADMIN = "domain-admin"
    NORMAL_USER = "normal-user"
    FILE_SERVER = "file-server"
    # Catch-all for unknown/future host types
    UNKNOWN = "unknown"


class ContainerState(str, Enum):
    """Docker container states."""
    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    RESTARTING = "restarting"
    EXITED = "exited"
    DEAD = "dead"
    REMOVING = "removing"
    RECREATING = "recreating"  # Special state during agent assignment


class AgentAssignmentState(str, Enum):
    """States for agent assignment lifecycle."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RECREATING = "recreating"
    READY = "ready"
    FAILED = "failed"
    REMOVING = "removing"
    REMOVED = "removed"


class SessionState(str, Enum):
    """OpenCode session states."""
    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"  # Waiting for agent response
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class LogLevel(str, Enum):
    """Log entry levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ReconciliationStatus(str, Enum):
    """Reconciliation operation status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"  # Some containers reconciled, some failed


# =============================================================================
# Base Models
# =============================================================================

class TimestampedModel(BaseModel):
    """Base model with timestamp fields."""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None


class IdentifiedModel(BaseModel):
    """Base model with ID field."""
    id: str = Field(..., description="Unique identifier for the resource")


# =============================================================================
# Agent Template Models
# =============================================================================

class AgentCapability(BaseModel):
    """Capability description for an agent type."""
    name: str = Field(..., description="Human-readable capability name")
    description: str = Field(..., description="What this capability enables")


class AgentTemplate(BaseModel):
    """Template describing an available agent type."""
    agent_type: AgentType = Field(..., description="Agent type identifier")
    name: str = Field(..., description="Human-readable agent name")
    description: str = Field(..., description="Agent functionality description")
    capabilities: List[AgentCapability] = Field(
        default_factory=list,
        description="List of agent capabilities"
    )
    opencode_image_required: bool = Field(
        default=True,
        description="Whether this agent requires OpenCode image"
    )
    supported_base_images: List[str] = Field(
        default_factory=lambda: ["ubuntu:24.04", "ubuntu:22.04", "debian:12"],
        description="Base OS images this agent supports"
    )


class AgentTemplatesResponse(BaseModel):
    """Response containing all available agent templates."""
    agents: Dict[AgentType, AgentTemplate] = Field(
        default_factory=dict,
        description="Map of agent type to template"
    )


# =============================================================================
# Agent Assignment Models
# =============================================================================

class AgentAssignment(BaseModel):
    """Request to assign an agent to a host."""
    topology_id: str = Field(..., description="Topology identifier")
    network_id: str = Field(..., description="Network identifier within topology")
    host_id: str = Field(..., description="Host identifier within network")
    agent_type: AgentType = Field(..., description="Agent type to assign")
    assigned_by: Optional[str] = Field(
        default="user",
        description="Who initiated the assignment (user/system/reconciliation)"
    )

    @validator('agent_type')
    def validate_agent_type(cls, v):
        """Ensure agent type is supported."""
        if isinstance(v, str):
            try:
                return AgentType(v)
            except ValueError:
                raise ValueError(f"Unsupported agent type: {v}")
        return v


class AgentAssignmentResponse(BaseModel):
    """Response from agent assignment request."""
    status: AgentAssignmentState = Field(..., description="Current assignment state")
    message: str = Field(..., description="Human-readable status message")
    topology_id: str = Field(..., description="Topology identifier")
    network_id: str = Field(..., description="Network identifier")
    host_id: str = Field(..., description="Host identifier")
    agent_type: AgentType = Field(..., description="Assigned agent type")
    job_id: Optional[str] = Field(
        default=None,
        description="Background job ID for tracking"
    )
    estimated_completion_seconds: Optional[int] = Field(
        default=10,
        description="Estimated time for container recreation"
    )


# =============================================================================
# Container Info Models
# =============================================================================

class ContainerInfo(BaseModel):
    """Information about a discovered container."""
    container_id: str = Field(..., description="Docker container ID")
    container_name: str = Field(..., description="Docker container name")
    topology_id: str = Field(..., description="Associated topology ID")
    network_id: str = Field(..., description="Network ID within topology")
    host_id: str = Field(..., description="Host ID within network")
    host_name: str = Field(..., description="Host name from topology")
    host_type: HostType = Field(..., description="Host type classification")
    ip_address: Optional[str] = Field(
        default=None,
        description="Container IP address within topology network"
    )
    image: str = Field(..., description="Container image")
    state: ContainerState = Field(..., description="Current container state")
    current_agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents currently assigned to this host"
    )
    can_assign_agent: bool = Field(
        default=True,
        description="Whether agents can be assigned to this host"
    )
    opencode_ready: bool = Field(
        default=False,
        description="Whether OpenCode server is ready (if has agents)"
    )
    opencode_port: Optional[int] = Field(
        default=4096,
        description="OpenCode server port (if exposed)"
    )
    labels: Dict[str, str] = Field(
        default_factory=dict,
        description="Docker container labels"
    )


class ContainerDiscoveryResponse(BaseModel):
    """Response from container discovery request."""
    hosts: List[ContainerInfo] = Field(
        default_factory=list,
        description="Discovered topology hosts"
    )
    total_count: int = Field(
        default=0,
        description="Total number of discovered hosts"
    )


# =============================================================================
# Session Info Models
# =============================================================================

class SessionMessage(BaseModel):
    """Message in an agent session."""
    id: str = Field(..., description="Message identifier")
    timestamp: datetime = Field(..., description="Message creation time")
    role: Literal["user", "assistant", "system", "tool"] = Field(
        ...,
        description="Message sender role"
    )
    content: str = Field(..., description="Message content")
    tool_calls: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Tool invocations (if any)"
    )
    tokens_used: Optional[int] = Field(
        default=None,
        description="LLM tokens used for this message"
    )


class SessionMetrics(BaseModel):
    """Metrics collected during a session."""
    total_messages: int = Field(default=0, description="Total message count")
    total_tokens_used: int = Field(default=0, description="Cumulative token usage")
    estimated_cost: Optional[float] = Field(
        default=None,
        description="Estimated LLM cost in USD"
    )
    execution_time_seconds: float = Field(
        default=0.0,
        description="Session execution duration"
    )
    tool_calls_count: int = Field(
        default=0,
        description="Number of tool calls made"
    )


class SessionInfo(TimestampedModel):
    """Information about an OpenCode session."""
    session_id: str = Field(..., description="Unique session identifier")
    container_id: str = Field(..., description="Container ID where session runs")
    host_id: str = Field(..., description="Host ID for session context")
    agent_type: AgentType = Field(..., description="Agent type in session")
    state: SessionState = Field(..., description="Current session state")
    messages: List[SessionMessage] = Field(
        default_factory=list,
        description="Session messages"
    )
    metrics: SessionMetrics = Field(
        default_factory=SessionMetrics,
        description="Session metrics"
    )
    last_activity: Optional[datetime] = Field(
        default=None,
        description="Last activity timestamp"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error details if session failed"
    )


class SessionCreateRequest(BaseModel):
    """Request to create a new agent session."""
    container_id: str = Field(..., description="Target container ID")
    host_id: str = Field(..., description="Host ID for context")
    agent_type: AgentType = Field(..., description="Agent type to use")
    initial_prompt: Optional[str] = Field(
        default=None,
        description="Initial prompt to send to agent"
    )
    session_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional session metadata"
    )


class SessionPromptRequest(BaseModel):
    """Request to send a prompt to an existing session."""
    prompt: str = Field(..., description="Prompt text to send")
    include_history: bool = Field(
        default=True,
        description="Whether to include conversation history"
    )
    timeout_seconds: Optional[int] = Field(
        default=120,
        description="Maximum time to wait for response"
    )


# =============================================================================
# Agent State Models
# =============================================================================

class AgentStateAssignment(TimestampedModel, IdentifiedModel):
    """Persistent state of an agent assignment."""
    container_id: str = Field(..., description="Docker container ID")
    container_name: str = Field(..., description="Docker container name")
    topology_id: str = Field(..., description="Associated topology ID")
    network_id: str = Field(..., description="Network ID")
    host_id: str = Field(..., description="Host ID")
    host_name: str = Field(..., description="Host name")
    agent_type: AgentType = Field(..., description="Assigned agent type")
    state: AgentAssignmentState = Field(..., description="Assignment state")
    assigned_by: str = Field(..., description="Who made the assignment")
    session_id: Optional[str] = Field(
        default=None,
        description="Active session ID (if any)"
    )
    opencode_image: str = Field(..., description="OpenCode image used")
    original_image: str = Field(..., description="Original base image")
    assigned_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Assignment timestamp"
    )
    recreated_at: Optional[datetime] = Field(
        default=None,
        description="When container was recreated with agent"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Error details if assignment failed"
    )


class AgentState(TimestampedModel):
    """Global agent state (stored in agent_state.json)."""
    version: str = Field(default="1.0", description="State format version")
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Last state update"
    )
    assignments: List[AgentStateAssignment] = Field(
        default_factory=list,
        description="All active agent assignments"
    )
    sessions: Dict[str, SessionInfo] = Field(
        default_factory=dict,
        description="Active sessions by session_id"
    )
    last_reconciliation_at: Optional[datetime] = Field(
        default=None,
        description="Last successful reconciliation timestamp"
    )


# =============================================================================
# Reconciliation Models
# =============================================================================

class ContainerStateMismatch(BaseModel):
    """Mismatch detected between desired and actual container state."""
    host_id: str = Field(..., description="Host identifier")
    container_id: str = Field(..., description="Current container ID")
    desired_agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents that should be assigned"
    )
    actual_agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents actually assigned"
    )
    desired_image: str = Field(..., description="Image that should be running")
    actual_image: str = Field(..., description="Image actually running")
    mismatch_type: Literal["missing_agents", "extra_agents", "wrong_image", "container_missing"] = Field(
        ...,
        description="Type of state mismatch"
    )
    action_required: Literal["recreate", "assign", "remove", "ignore"] = Field(
        ...,
        description="Action needed to resolve mismatch"
    )


class ReconciliationResult(TimestampedModel):
    """Result of a reconciliation operation."""
    topology_id: str = Field(..., description="Reconciled topology ID")
    status: ReconciliationStatus = Field(..., description="Reconciliation status")
    containers_checked: int = Field(
        default=0,
        description="Number of containers examined"
    )
    mismatches_found: int = Field(
        default=0,
        description="Number of state mismatches detected"
    )
    containers_reconciled: int = Field(
        default=0,
        description="Number of containers successfully reconciled"
    )
    failures: List[str] = Field(
        default_factory=list,
        description="Error messages for failed reconciliations"
    )
    mismatches: List[ContainerStateMismatch] = Field(
        default_factory=list,
        description="Detailed mismatch information"
    )
    duration_seconds: float = Field(
        default=0.0,
        description="Reconciliation operation duration"
    )
    error_message: Optional[str] = Field(
        default=None,
        description="Overall error if reconciliation failed"
    )


class ReconciliationStatusResponse(BaseModel):
    """Current reconciliation status across all topologies."""
    last_reconciliation_at: Optional[datetime] = Field(
        default=None,
        description="Last global reconciliation time"
    )
    auto_reconcile_enabled: bool = Field(
        default=False,
        description="Whether automatic reconciliation is enabled"
    )
    reconcile_interval_seconds: int = Field(
        default=300,
        description="Interval between automatic reconciliations"
    )
    recent_results: List[ReconciliationResult] = Field(
        default_factory=list,
        description="Recent reconciliation results"
    )
    active_topologies: List[str] = Field(
        default_factory=list,
        description="Topology IDs with active containers"
    )


# =============================================================================
# Agent Response Models
# =============================================================================

class AgentResponse(BaseModel):
    """Response from an agent (via OpenCode)."""
    session_id: str = Field(..., description="Session identifier")
    agent_type: AgentType = Field(..., description="Agent type that responded")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Response timestamp"
    )
    status: SessionState = Field(..., description="Response status")
    content: Optional[str] = Field(
        default=None,
        description="Agent response content"
    )
    tool_results: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Results from tool calls"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if response failed"
    )
    tokens_used: Optional[int] = Field(
        default=None,
        description="Tokens used for this response"
    )
    execution_time_ms: Optional[int] = Field(
        default=None,
        description="Response generation time in milliseconds"
    )


# =============================================================================
# Log Models
# =============================================================================

class LogEntry(TimestampedModel):
    """Single log entry from agent activity."""
    timestamp: datetime = Field(..., description="Log entry timestamp")
    level: LogLevel = Field(..., description="Log level")
    agent_type: AgentType = Field(..., description="Agent that generated log")
    session_id: str = Field(..., description="Associated session ID")
    container_id: str = Field(..., description="Container where log originated")
    message: str = Field(..., description="Log message")
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional log metadata (tool calls, timing, etc.)"
    )


class LogStreamRequest(BaseModel):
    """Request to stream agent logs."""
    session_id: str = Field(..., description="Session to stream logs from")
    level_filter: Optional[LogLevel] = Field(
        default=None,
        description="Filter by log level (None for all)"
    )
    since: Optional[datetime] = Field(
        default=None,
        description="Start streaming from this timestamp"
    )
    include_tool_calls: bool = Field(
        default=True,
        description="Whether to include tool call details"
    )


class LogStreamResponse(BaseModel):
    """Response containing log entries."""
    session_id: str = Field(..., description="Session identifier")
    logs: List[LogEntry] = Field(
        default_factory=list,
        description="Log entries matching request"
    )
    total_count: int = Field(
        default=0,
        description="Total number of log entries"
    )
    has_more: bool = Field(
        default=False,
        description="Whether more logs are available"
    )


# =============================================================================
# Topology Models (for reference)
# =============================================================================

class RouterInfo(BaseModel):
    """Router configuration from topology."""
    id: str = Field(..., description="Router identifier")
    name: str = Field(..., description="Router name")
    parent_router_id: str = Field(
        default="",
        description="Parent router ID (for hierarchical routing)"
    )
    ssh_enabled: bool = Field(default=False, description="SSH access enabled")
    username: str = Field(default="admin", description="SSH username")
    password: str = Field(default="strato", description="SSH password")


class NetworkInfo(BaseModel):
    """Network configuration from topology."""
    id: str = Field(..., description="Network identifier")
    name: str = Field(..., description="Network name")
    cidr: str = Field(..., description="Network CIDR block")
    internet: bool = Field(default=False, description="Internet access enabled")
    router_ids: List[str] = Field(
        default_factory=list,
        description="Connected router IDs"
    )
    default_router_id: str = Field(
        default="",
        description="Default router for this network"
    )
    hosts: List["HostInfo"] = Field(
        default_factory=list,
        description="Hosts in this network"
    )


class HostInfo(BaseModel):
    """Host configuration from topology."""
    id: str = Field(..., description="Host identifier")
    name: str = Field(..., description="Host name")
    type: HostType = Field(..., description="Host type")
    image: str = Field(default="ubuntu:24.04", description="Container image")
    ssh_enabled: bool = Field(default=True, description="SSH access enabled")
    username: str = Field(default="student", description="SSH username")
    password: str = Field(default="strato", description="SSH password")
    generate_data: bool = Field(default=False, description="Generate test data")
    data_prompt: str = Field(default="", description="Data generation prompt")
    data_content: str = Field(default="", description="Generated data content")
    agents: List[AgentType] = Field(
        default_factory=list,
        description="Agents assigned to this host"
    )


class TopologyInfo(TimestampedModel):
    """Complete topology configuration."""
    id: str = Field(..., description="Topology identifier")
    name: str = Field(..., description="Topology name")
    version: str = Field(default="2.0", description="Topology schema version")
    routers: List[RouterInfo] = Field(
        default_factory=list,
        description="Topology routers"
    )
    networks: List[NetworkInfo] = Field(
        default_factory=list,
        description="Topology networks"
    )
    router: Dict[str, Any] = Field(
        default_factory=dict,
        description="Default router configuration"
    )
    infrastructure: Dict[str, Any] = Field(
        default_factory=dict,
        description="Infrastructure settings"
    )


# =============================================================================
# API Response Wrapper Models
# =============================================================================

class APIResponse(BaseModel):
    """Standard API response wrapper."""
    success: bool = Field(..., description="Request success status")
    message: Optional[str] = Field(
        default=None,
        description="Optional response message"
    )
    data: Optional[Any] = Field(default=None, description="Response data")
    error: Optional[str] = Field(default=None, description="Error details")


class JobStatus(BaseModel):
    """Status of a background job."""
    job_id: str = Field(..., description="Job identifier")
    job_type: Literal["agent_assign", "agent_remove", "container_recreate", "reconcile"] = Field(
        ...,
        description="Type of job"
    )
    status: Literal["queued", "running", "completed", "failed"] = Field(
        ...,
        description="Job status"
    )
    progress: int = Field(default=0, ge=0, le=100, description="Job progress %")
    message: str = Field(..., description="Status message")
    started_at: Optional[datetime] = Field(default=None, description="Job start time")
    completed_at: Optional[datetime] = Field(default=None, description="Job completion time")
    error: Optional[str] = Field(default=None, description="Error details if failed")


# =============================================================================
# Metrics Models
# =============================================================================

class SystemMetrics(BaseModel):
    """Operational metrics for the Agent Manager."""
    assignments_total: int = Field(
        default=0,
        description="Total agent assignments"
    )
    assignments_active: int = Field(
        default=0,
        description="Currently active assignments"
    )
    sessions_active: int = Field(
        default=0,
        description="Active OpenCode sessions"
    )
    sessions_total: int = Field(
        default=0,
        description="Total sessions created"
    )
    reconcile_last_run_at: Optional[datetime] = Field(
        default=None,
        description="Last reconciliation run time"
    )
    reconcile_success_count: int = Field(
        default=0,
        description="Successful reconciliations"
    )
    reconcile_failure_count: int = Field(
        default=0,
        description="Failed reconciliations"
    )
    opencode_images_built: List[str] = Field(
        default_factory=list,
        description="Available OpenCode images"
    )
    topology_count: int = Field(
        default=0,
        description="Number of active topologies"
    )
    container_count: int = Field(
        default=0,
        description="Number of discovered containers"
    )


# =============================================================================
# Event Models (for WebSocket streaming)
# =============================================================================

class EventType(str, Enum):
    """Types of events that can be streamed."""
    AGENT_ASSIGNED = "agent_assigned"
    AGENT_REMOVED = "agent_removed"
    AGENT_READY = "agent_ready"
    AGENT_FAILED = "agent_failed"
    SESSION_CREATED = "session_created"
    SESSION_UPDATED = "session_updated"
    SESSION_COMPLETED = "session_completed"
    SESSION_FAILED = "session_failed"
    CONTAINER_RECREATED = "container_recreated"
    CONTAINER_DISCOVERED = "container_discovered"
    RECONCILIATION_STARTED = "reconciliation_started"
    RECONCILIATION_COMPLETED = "reconciliation_completed"
    LOG_ENTRY = "log_entry"


class AgentEvent(BaseModel):
    """Event for streaming via WebSocket."""
    event_type: EventType = Field(..., description="Event type")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Event timestamp"
    )
    event_id: str = Field(..., description="Unique event identifier")
    topology_id: Optional[str] = Field(default=None, description="Associated topology")
    host_id: Optional[str] = Field(default=None, description="Associated host")
    agent_type: Optional[AgentType] = Field(default=None, description="Associated agent")
    session_id: Optional[str] = Field(default=None, description="Associated session")
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Event-specific data"
    )


# =============================================================================
# Health and Monitoring Models
# =============================================================================

class ComponentHealth(BaseModel):
    """Health status of a single component."""
    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ...,
        description="Component health status"
    )
    ready: Optional[bool] = Field(default=None, description="Component ready state")
    error: Optional[str] = Field(default=None, description="Error details if unhealthy")
    container_count: Optional[int] = Field(default=None, description="Container count (Docker)")
    assignment_count: Optional[int] = Field(default=None, description="Assignment count (State Manager)")
    active_connections: Optional[int] = Field(default=None, description="Active connections (WebSocket)")


class HealthResponse(BaseModel):
    """Health check response."""
    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        ...,
        description="Overall system health"
    )
    timestamp: datetime = Field(..., description="Health check timestamp")
    components: Dict[str, ComponentHealth] = Field(
        default_factory=dict,
        description="Component health statuses"
    )


class AgentMetrics(BaseModel):
    """Agent-related metrics."""
    total_assignments: int = Field(default=0, description="Total agent assignments")
    by_topology: Dict[str, int] = Field(default_factory=dict, description="Assignments per topology")
    by_type: Dict[str, int] = Field(default_factory=dict, description="Assignments per agent type")
    by_status: Dict[str, int] = Field(default_factory=dict, description="Assignments per status")


class ContainerMetrics(BaseModel):
    """Container-related metrics."""
    total: int = Field(default=0, description="Total containers")
    by_state: Dict[str, int] = Field(default_factory=dict, description="Containers per state")


class SessionHealthMetrics(BaseModel):
    """Session-related health metrics."""
    total: int = Field(default=0, description="Total sessions")
    by_status: Dict[str, int] = Field(default_factory=dict, description="Sessions per status")


class WebSocketMetrics(BaseModel):
    """WebSocket-related metrics."""
    active_connections: int = Field(default=0, description="Active WebSocket connections")


class BackgroundTaskMetrics(BaseModel):
    """Background task-related metrics."""
    reconcile_running: bool = Field(default=False, description="Reconcile task running status")
    image_build_running: bool = Field(default=False, description="Image build task running status")
    reconcile_interval_seconds: int = Field(default=300, description="Reconcile interval")
    image_build_interval_seconds: int = Field(default=3600, description="Image build interval")


class MetricsResponse(BaseModel):
    """System metrics response."""
    timestamp: datetime = Field(..., description="Metrics timestamp")
    agents: AgentMetrics = Field(default_factory=AgentMetrics, description="Agent metrics")
    containers: ContainerMetrics = Field(default_factory=ContainerMetrics, description="Container metrics")
    sessions: SessionHealthMetrics = Field(default_factory=SessionHealthMetrics, description="Session metrics")
    websocket: WebSocketMetrics = Field(default_factory=WebSocketMetrics, description="WebSocket metrics")
    background_tasks: BackgroundTaskMetrics = Field(
        default_factory=BackgroundTaskMetrics,
        description="Background task metrics"
    )


# =============================================================================
# Coder56 Pentest Console — human-in-the-loop guardrail + goal builder
# =============================================================================
# These models are the SINGLE contract shared by:
#   - guardrail.ts (writes ApprovalReq JSON files, reads ApprovalDecision files)
#   - backend/routers/coder56.py (REST surface for the standalone console)
#   - the standalone React frontend (coder56-console/)
# Field names must stay in lock-step across all three.
# =============================================================================

# -----------------------------------------------------------------------------
# Per-phase orchestration (MITRE engagement chain)
#
# Defined before Criticality/LaunchRequest because LaunchRequest references
# PhaseSpec/PhaseMode (annotations are evaluated eagerly at class-definition
# time). A launch may carry a structured phase chain; when non-empty the run
# executes ONE phase at a time (each phase = its own coder56 opencode session)
# instead of sending the whole directive as a single prompt. The backend
# phase-driver polls the active session's message stream to detect turn-end
# (= phase completion), then auto-advances or pauses for operator review.
# Empty `phases` => the backend synthesizes a threat-model-driven default plan
# (_default_threatmodel_phases in coder56.py) so the run still executes as a
# phased native_subagents engagement (Phase 0 threat model -> ... ), not legacy
# single-shot.
# -----------------------------------------------------------------------------

class PhaseSpec(BaseModel):
    """One operator-defined phase in the engagement chain.

    `objective` is the primary, free-text input (what the operator wants this
    phase to achieve). tactic_id/technique_ids are optional MITRE tags carried
    through for catalog/guardrail context.
    """
    objective: str = Field(default="", description="Free-text objective for this phase")
    tactic_id: str = Field(default="", description="Optional ATT&CK tactic ID, e.g. TA0043")
    technique_ids: List[str] = Field(default_factory=list)
    note: str = Field(default="", description="Optional operator note / detail")
    tools: List[str] = Field(default_factory=list, description="Recommended tools for this phase")
    checklist: List[str] = Field(default_factory=list, description="Goals/tasks checklist for this phase")
    # WebApp/API-mode phase tags (additive; empty/false => NETWORK-mode behavior).
    api_category: str = Field(default="", description="For webapp/api mode: the OWASP id this phase targets (A01-A10 or API1-API10)")
    is_research_phase: bool = Field(default=False, description="True for Phase R: recon-first research whose persisted output is ground truth for later phases")


class EngagementMode(str, Enum):
    """Operator-selected engagement mode backing the planner frame.

    NETWORK (the default, byte-for-byte no-regression) drives the existing
    MITRE ATT&CK kill-chain + host-compromise skeleton. WEBAPP/API switch the
    planner to an OWASP WSTG v4.2 spine with the OWASP Top-10 (2021) / OWASP
    API Security Top-10 (2023) risk model respectively (see api_security_catalog.py).
    Threaded end-to-end through launch()/draft_goal()/the OWASP-plan drafter and
    persisted into the run manifest; read back from manifest/meta (not req) where
    req is out of scope (empty-phases fallback + _dedup_phase_plan).
    """
    NETWORK = "network"   # MITRE ATT&CK kill-chain + host-compromise (CURRENT DEFAULT)
    WEBAPP  = "webapp"    # OWASP WSTG v4.2 spine, OWASP Top-10 (2021) risk model
    API     = "api"       # OWASP WSTG v4.2 spine, OWASP API Security Top-10 (2023) risk model


class PhaseMode(str, Enum):
    """How the run behaves at each phase boundary."""
    AUTO_CONTINUE = "auto_continue"   # on phase completion, auto-start the next phase
    REVIEW_EACH = "review_each"       # pause at every phase boundary for operator review


class PhaseStatus(str, Enum):
    """Lifecycle state of a single phase's execution."""
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_REVIEW = "awaiting_review"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    FAILED = "failed"


class Orchestration(str, Enum):
    """How a phased run's phases are coordinated/executed.

    BACKEND_SESSIONS (default): the agent-manager backend creates one fresh
    coder56 opencode session per phase, injects prior-phase findings, and gates
    between phases (the original, robust path — no regression).

    NATIVE_SUBAGENTS: a single coder56_lead (primary) session coordinates the
    engagement, spawning a coder56_phase subagent per phase via opencode's Task
    tool. Subagents run in child sessions of the Lead and report back; the
    backend watches the Lead session's Task-tool I/O to derive phase_runtime.
    phase_mode (review_each / auto_continue) still governs whether the Lead
    pauses between phases."""
    BACKEND_SESSIONS = "backend_sessions"
    NATIVE_SUBAGENTS = "native_subagents"



class PhaseRuntime(BaseModel):
    """Mutable per-phase execution state, persisted in the run manifest."""
    index: int
    status: PhaseStatus = PhaseStatus.PENDING
    objective: str = ""
    tactic_id: str = ""
    technique_ids: List[str] = Field(default_factory=list)
    session_id: str = ""
    result: str = Field(default="", description="Captured phase summary (last assistant text)")
    started_at: str = ""
    completed_at: str = ""


class AdvanceRequest(BaseModel):
    """Operator action at a phase boundary (start the next phase)."""
    revised_objective: Optional[str] = Field(default=None, description="Override the next phase's objective (review & correct)")
    mode: Optional[PhaseMode] = Field(default=None, description="Optionally flip the run phase_mode too")


class PhaseModeRequest(BaseModel):
    mode: PhaseMode


class Criticality(str, Enum):
    """Operator-selected criticality for a coder56 pentest run.

    Maps to the guardrail's runtime behavior via /outputs/<run_id>/guardrail/mode.txt:
      low    -> pass-through (no judge, no approvals)
      medium -> judge every command; auto-execute safe verdicts; PAUSE on
                refuse/sanitize/escalate/parse-fail for operator review
      high   -> judge for a recommendation, then PAUSE EVERY command for approval
      auto   -> ACTIVE guardrail, FULLY AUTONOMOUS: judge every command and apply
                the verdict with NO human in the loop — execute/sanitize run,
                refuse/escalate/parse-fail refuse and return guardrail feedback.
                No approvals are ever created (no HITL pause, no global halt).
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    AUTO = "auto"


class MitreTechnique(BaseModel):
    """A single ATT&CK technique/sub-technique in the goal-builder catalog."""
    id: str = Field(..., description="ATT&CK technique ID, e.g. T1190 or T1110.001")
    name: str
    description: str = ""
    typical_commands: List[str] = Field(default_factory=list)
    scope_notes: str = Field(default="", description="In/out-of-scope guidance for the guardrail")


class MitreTactic(BaseModel):
    """An ATT&CC tactic in the goal-builder catalog."""
    id: str = Field(..., description="ATT&CK tactic ID, e.g. TA0001")
    name: str
    phase: int = Field(..., description="Kill-chain ordering (1..n)")
    description: str = ""
    guidance: str = Field(default="", description="Phase-specific guidance for the agent")
    techniques: List[MitreTechnique] = Field(default_factory=list)


class MitrePhaseSelection(BaseModel):
    """An operator-selected phase in the engagement chain."""
    tactic_id: str
    technique_ids: List[str] = Field(default_factory=list)
    note: str = Field(default="", description="Operator free-text for this phase")
    tools: List[str] = Field(default_factory=list, description="Recommended tools for this phase")
    checklist: List[str] = Field(default_factory=list, description="Goals/tasks checklist for this phase")


class GoalDraftRequest(BaseModel):
    """Request an LLM-authored draft of a scoped engagement directive."""
    objective: str = Field(..., description="Free-text operator objective")
    target: str = Field(default="", description="Authorized target IP/CIDR/host")
    rules_of_engagement: str = Field(default="", description="Optional RoE / constraints")
    depth: str = Field(default="standard", description="brief | standard | thorough")
    engagement_mode: EngagementMode = Field(default=EngagementMode.NETWORK)


class GoalCompileRequest(BaseModel):
    """Compile a structured engagement into the directive string sent to coder56
    AND forwarded to the guardrail goal (so the agent's plan and the scope-keeper's
    authorized scope are identical)."""
    objective: str
    target: str = Field(default="")
    rules_of_engagement: str = Field(default="")
    phases: List[MitrePhaseSelection] = Field(default_factory=list)
    stop_conditions: str = Field(default="")
    credentials: str = Field(default="", description="Pre-existing owned/seeded credentials, injected into the directive (lead + all phases).")


class GoalDirective(BaseModel):
    """Compiled engagement directive + the structured view of it."""
    directive: str = Field(..., description="The full text sent to coder56 + guardrail goal")
    summary: str = Field(default="")


class LaunchRequest(BaseModel):
    """Launch a coder56 pentest run with a chosen criticality."""
    # topology_id/host_id are REQUIRED for the SCL topology path, but OPTIONAL for
    # an isolated launch (isolated=True) which spins up/reuses a standalone coder56
    # sandbox with no topology and no host selection. See routers/coder56.py launch().
    topology_id: Optional[str] = Field(default=None, description="Topology identifier (required unless isolated)")
    host_id: Optional[str] = Field(default=None, description="Host identifier within network (required unless isolated)")
    isolated: bool = Field(default=False, description="Topology-free launch into the persistent coder56 sandbox")
    criticality: Criticality = Criticality.MEDIUM
    directive: str = Field(..., description="Compiled engagement directive (the agent goal)")
    timeout_seconds: int = Field(default=600, description="Initial-prompt sync timeout")
    auto_start_topology: bool = Field(default=True, description="Start the topology if not running")
    # Per-phase orchestration (optional). When non-empty the run executes one
    # phase at a time (one coder56 session per phase) with a review gate between
    # phases; the whole `directive` above is still written to goal.txt as the
    # guardrail's authoritative engagement scope. Empty => the backend synthesizes
    # a threat-model-driven default plan (_default_threatmodel_phases) so the run
    # is still a phased native_subagents engagement, not legacy single-shot.
    phases: List[PhaseSpec] = Field(default_factory=list)
    phase_mode: PhaseMode = Field(default=PhaseMode.REVIEW_EACH)
    # How phases are coordinated: backend-driven session-per-phase vs a single
    # coder56_lead session that spawns coder56_phase subagents via the Task tool.
    # P2-6: backend session-per-phase REMOVED — native_subagents is now the only
    # active path (default forced + pinned at finalize). BACKEND_SESSIONS is kept
    # only for back-compat with old manifests; the launch path no longer selects it.
    # Only meaningful when `phases` is non-empty.
    orchestration: Orchestration = Field(default=Orchestration.NATIVE_SUBAGENTS)
    # Operator-selected engagement mode: NETWORK (default — kill-chain + host
    # compromise, byte-for-byte no-regression) vs WEBAPP/API (OWASP WSTG v4.2
    # spine + Top-10 2021 / API Security Top-10 2023 risk model). Threaded into
    # the run manifest/meta and read back by the empty-phases fallback +
    # _dedup_phase_plan (req is out of scope there). Default NETWORK keeps every
    # existing run/endpoint identical.
    engagement_mode: EngagementMode = Field(default=EngagementMode.NETWORK)
    # Optional link to an Engagement (a grouped pentest project). When set, the
    # run is registered under OUTPUTS_DIR/engagements/<engagement_id>.json and
    # the run manifest carries engagement_id back so the UI can scope to it.
    # Absent => a standalone (legacy) run, still listed under /api/coder56/runs.
    engagement_id: Optional[str] = Field(default=None, description="Group this run under an Engagement")
    # NoGuard experiment: run the external guardrail judge in SHADOW mode for
    # this run — every bash/MCP call is still adjudicated and the verdict is
    # persisted to verdicts.ndjson (with "shadow": true), but NOTHING is wired
    # back to the agent (no refuse/escalate, no rewrite, no HITL): the command
    # always executes and the agent sees its own real output. Live-toggleable
    # via PATCH /runs/{run_id}/guardrail-shadow (writes/removes shadow.txt).
    guardrail_shadow: bool = Field(default=False, description="Guardrail adjudicates in shadow mode (record-only, never enforced)")


class LaunchResponse(BaseModel):
    """Result of launching a run."""
    run_id: str
    session_id: str
    container_id: str
    topology_id: str
    host_id: str
    criticality: Criticality
    message: str = Field(default="")


class SandboxStatus(BaseModel):
    """Status of the persistent isolated coder56 sandbox container.

    The sandbox is a single long-lived coder56 container (no topology, no host
    selection) reused across launches. One sandbox == one fixed RUN_ID, so each
    isolated launch writes a fresh directive/mode + starts a new opencode session
    into the same container (same reuse semantics as a long-lived topology host).
    """
    exists: bool
    running: bool
    container_id: str = Field(default="")
    name: str = Field(default="")
    run_id: str = Field(default="")
    image: str = Field(default="")
    created_at: str = Field(default="")
    status_text: str = Field(default="missing")


class ApprovalGuardrailVerdict(BaseModel):
    """The guardrail judge's verdict on the command (the operator's recommendation)."""
    decision: str = Field(default="", description="execute|refuse|sanitize|escalate")
    reason: str = ""
    feedback: str = ""
    executed: bool = False
    exit_code: int = 0


class ApprovalReq(BaseModel):
    """A pending/approval request written by guardrail.ts and surfaced to the operator."""
    id: str
    ts: str
    run_id: str
    session_id: str = ""
    container_id: str = ""
    command: str
    profile: str = "coder56"
    mode: str = Field(default="medium", description="low|medium|high")
    trigger: str = Field(default="flagged", description="flagged|always")
    guardrail_verdict: ApprovalGuardrailVerdict = Field(default_factory=ApprovalGuardrailVerdict)
    goal: str = ""
    trace: str = ""
    parsed_via: str = Field(default="", description="How the verdict was parsed (json-fence|json-object|regex-fallback|none)")
    failure_reason: str = Field(default="", description="Why the guardrail produced no/weak verdict (transport/parse failure)")
    status: str = Field(default="pending", description="pending|decided|expired")
    seq: int = 0
    # Populated when a decision file exists:
    decision: Optional["ApprovalDecision"] = None


class ApprovalDecision(BaseModel):
    """An operator decision written as <id>.dec.json for guardrail.ts to read."""
    id: str
    ts: str
    action: str = Field(..., description="approve|reject|modify|guide")
    modified_command: Optional[str] = None
    feedback: Optional[str] = None
    decided_by: str = "operator"
    decided_ts: str = ""


class DecideRequest(BaseModel):
    """Operator decision on a pending approval."""
    action: str = Field(..., description="approve|reject|modify|guide")
    modified_command: Optional[str] = None
    feedback: Optional[str] = None
    run_id: Optional[str] = Field(default=None, description="If known, scopes the req lookup")


class GuideRequest(BaseModel):
    """A free-form operator follow-up prompt to the agent session."""
    prompt: str


class ShadowRequest(BaseModel):
    """Live-toggle shadow mode for a run's guardrail.

    true  -> write /outputs/<run_id>/guardrail/shadow.txt (adjudicate + record
             only; the agent is never gated); false -> remove it (normal gating
             resumes on the next command)."""
    value: bool


class JudgeFailRequest(BaseModel):
    """Live-toggle the guardrail's judge-unavailable fallback for a run.

    'escalate' (default, fail-safe) holds a command for operator review when the
    guardrail JUDGE itself can't produce a verdict; 'allow' executes it instead of
    stalling on judge downtime. Applies only to verdict===null (judge unreachable).
    """
    value: str


# -----------------------------------------------------------------------------
# Engagements + Findings (grouped executions + curated pentest report data)
#
# An Engagement is a pentest project: it groups many Runs (executions) and holds
# a curated Findings list. The professional report is generated per Engagement.
# These models use only primitives + plain-string ids (engagement_id,
# discovered_via_run_id) so they carry NO forward references and can be defined
# here after GuideRequest without disturbing the eager-eval ordering rule above.
# Persisted as OUTPUTS_DIR/engagements/<engagement_id>.json (findings stored
# inside the engagement JSON for atomic single-file writes + trivial reporting).
# -----------------------------------------------------------------------------

class EngagementStatus(str, Enum):
    """Lifecycle state of an engagement."""
    PLANNING = "planning"      # objective/scope being defined; no runs yet
    ACTIVE = "active"          # runs in progress / being executed
    REPORTING = "reporting"    # runs done; findings being curated
    CLOSED = "closed"          # delivered / archived


class Severity(str, Enum):
    """Finding severity (ordered, critical -> info)."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    """Remediation status of a finding."""
    OPEN = "open"
    REMEDIATING = "remediating"
    FIXED = "fixed"
    ACCEPTED = "accepted"      # risk-accepted, won't fix


class FindingCreate(BaseModel):
    """Operator/LLM fields for a finding."""
    title: str
    severity: Severity = Severity.MEDIUM
    cvss: Optional[float] = Field(default=None, description="Optional CVSS v3.1 base score 0.0-10.0")
    affected_asset: str = Field(default="", description="Affected host/service/asset")
    description: str = ""
    impact: str = ""
    evidence: str = Field(default="", description="Evidence (markdown): commands, output, run refs")
    recommendation: str = Field(default="", description="Remediation guidance")
    status: FindingStatus = FindingStatus.OPEN
    discovered_via_run_id: Optional[str] = Field(default=None, description="Run the evidence came from")
    # Verifier provenance: populated by the findings-draft pipeline from the
    # agent's own verdict write-ups (coder56_verifier output). `verified` is True
    # only when the verifier independently CONFIRMED the claim; `verifier_verdict`
    # carries the verdict line (e.g. "CONFIRMED by coder56_verifier — OK TO
    # REPORT: YES", or "NOT_A_VULN — false positive"); `commands` are the exact
    # repro commands the verifier/agent used to prove the finding.
    verified: bool = Field(default=False, description="Independently confirmed by the coder56_verifier subagent")
    verifier_verdict: str = Field(default="", description="Verifier verdict line (CONFIRMED / NOT_A_VULN / refuted)")
    commands: List[str] = Field(default_factory=list, description="Exact repro commands that prove the finding")
    owasp_id: Optional[str] = Field(default=None, description="OWASP Top-10 category (A01-A10) this finding maps to, when drafted from an OWASP plan")


# Defined BEFORE Engagement because Engagement.findings references Finding
# (annotations are evaluated eagerly at class-definition time — no forward refs).
class Finding(FindingCreate):
    """A persisted finding within an engagement."""
    id: str
    engagement_id: str
    created_at: str
    updated_at: str


# -----------------------------------------------------------------------------
# OWASP Top 10 plan (drafted per-category runs)
#
# An engagement may carry a `plan`: a drafted run per OWASP Top 10 category
# (A01-A10), generated from one shared scope+target. Each PlannedRun is a
# *draft* — it holds the objective/checklist/tools but is NOT a real run until
# the operator materializes it (POST .../plan/{owasp_id}/run), which calls the
# existing launch() and records the resulting run_id back here. This lets an
# operator "draft 10, run one at a time, any order".
#
# Defined BEFORE Engagement because Engagement.plan references PlannedRun
# (annotations are evaluated eagerly at class-definition time — no forward refs).
# -----------------------------------------------------------------------------
class PlannedRunStatus(str, Enum):
    """Lifecycle state of a drafted per-category run."""
    PLANNED = "planned"       # drafted, not yet executed
    RUNNING = "running"       # materialized into a real run (launch() called)
    DONE = "done"             # operator marked the category assessed
    SKIPPED = "skipped"       # deliberately not assessed (e.g. white-box-only)


class PlannedRun(BaseModel):
    """One drafted run in the engagement's OWASP plan.

    `objective` is the primary input (what this category-run should achieve),
    scoped to the engagement target via the catalog's objective_template.
    """
    owasp_id: str = Field(..., description="OWASP category id, e.g. A03")
    title: str = Field(default="", description="OWASP category name, e.g. 'Injection'")
    objective: str = Field(default="", description="Scoped objective for this category-run")
    checklist: List[str] = Field(default_factory=list, description="WSTG-style sub-tests")
    tools: List[str] = Field(default_factory=list, description="Recommended tools")
    scope_notes: str = Field(default="", description="In/out-of-scope guidance for the guardrail")
    assessable: str = Field(default="black-box", description="black-box | white-box-only")
    status: PlannedRunStatus = Field(default=PlannedRunStatus.PLANNED)
    run_id: Optional[str] = Field(default=None, description="Real run_id once materialized via launch()")
    run_at: str = Field(default="", description="ISO timestamp of the last materialization")
    # LLM-drafted phased execution plan for this category (like a normal run's
    # goal/draft). Empty until the operator drafts phases; when non-empty the run
    # materializes as a phased native_subagents run instead of a single-shot.
    phases: List[PhaseSpec] = Field(default_factory=list)
    phase_draft_note: str = Field(default="", description="LLM draft summary / status note")


class EngagementCreate(BaseModel):
    """Operator fields for creating an engagement."""
    name: str
    client: str = Field(default="", description="Client / business unit")
    target_scope: str = Field(default="", description="Authorized target scope (CIDR/host/app)")
    objective: str = Field(default="", description="Engagement objective")
    roe: str = Field(default="", description="Rules of engagement")
    status: EngagementStatus = EngagementStatus.PLANNING
    # C1 TARGET-IDENTITY: a machine-verifiable fingerprint of the target app so a
    # repointed host (accion_del_sur -> greedy_cars) is detected, not silently
    # inherited. Captured/confirmed by Phase 0; persisted on the engagement JSON
    # (sibling of plan[]). Shape: expected_app/marker_method/marker_path/marker_match/
    # canary_hash/banner_fragments/captured_at. Empty dict = operator left it blank;
    # Phase 0 chooses a marker and populates it.
    target_fingerprint: Dict[str, Any] = Field(default_factory=dict)
    credentials: str = Field(default="", description="Seeded/owned credentials for this engagement (injected into every run's directive).")


class Engagement(EngagementCreate):
    """A persisted engagement. `run_ids` links to run manifests; `findings` is
    the curated list (kept in the same JSON for atomic writes). `plan` is the
    optional OWASP Top 10 drafted-runs ledger; `plan_launch` holds the default
    'where coder56 runs' settings applied when a planned run is materialized."""
    id: str
    created_at: str
    updated_at: str
    run_ids: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    plan: List[PlannedRun] = Field(default_factory=list, description="Drafted per-OWASP-category runs")
    plan_launch: Optional[Dict[str, Any]] = Field(default=None, description="Default launch target (topology_id/host_id/isolated/criticality)")


class EngagementUpdate(BaseModel):
    """PATCH fields for an engagement (all optional)."""
    name: Optional[str] = None
    client: Optional[str] = None
    target_scope: Optional[str] = None
    objective: Optional[str] = None
    roe: Optional[str] = None
    status: Optional[EngagementStatus] = None
    target_fingerprint: Optional[Dict[str, Any]] = None
    credentials: Optional[str] = None


class FindingUpdate(BaseModel):
    """PATCH fields for a finding (all optional)."""
    title: Optional[str] = None
    severity: Optional[Severity] = None
    cvss: Optional[float] = None
    affected_asset: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    status: Optional[FindingStatus] = None
    discovered_via_run_id: Optional[str] = None
    verified: Optional[bool] = None
    verifier_verdict: Optional[str] = None
    commands: Optional[List[str]] = None


class AddRunRequest(BaseModel):
    """Link an existing run to an engagement."""
    run_id: str


class FindingsDraftRequest(BaseModel):
    """Ask the LLM to draft findings from an engagement's on-disk run artifacts."""
    engagement_id: str
    owasp_id: Optional[str] = Field(default=None, description="Restrict the draft to one OWASP category's run (A01-A10)")


class OwaspPlanRequest(BaseModel):
    """Generate (or regenerate) the OWASP Top 10 plan for an engagement from one
    shared scope+target. The 10 drafted runs are produced deterministically from
    the catalog (owasp_catalog.py); no LLM call required."""
    target_scope: Optional[str] = Field(default=None, description="Override engagement target_scope for objective templating")
    objective: Optional[str] = Field(default=None, description="Optional engagement-level objective prefix folded into each run")
    topology_id: Optional[str] = Field(default=None, description="Default 'where coder56 runs' for materializing a planned run")
    host_id: Optional[str] = Field(default=None, description="Default coder56 host for materializing a planned run")
    isolated: bool = Field(default=False, description="Default: materialize planned runs into the isolated sandbox")
    criticality: Criticality = Field(default=Criticality.MEDIUM)


class PlannedRunUpdate(BaseModel):
    """PATCH fields for a drafted planned run (status / objective / phases)."""
    status: Optional[PlannedRunStatus] = None
    objective: Optional[str] = None
    phases: Optional[List[PhaseSpec]] = None


class PlannedPhaseDraftRequest(BaseModel):
    """Request the LLM to draft a phased plan for one OWASP planned run."""
    depth: str = Field(default="standard", description="brief | standard | thorough")


# =============================================================================
# Forward references for circular dependencies
# =============================================================================
NetworkInfo.update_forward_refs()
ApprovalReq.update_forward_refs()
