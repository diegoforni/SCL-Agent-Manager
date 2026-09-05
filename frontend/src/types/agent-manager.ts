/**
 * TypeScript type definitions for Agent Manager Plugin.
 *
 * Generated from backend Pydantic models (models.py).
 * Defines interfaces for agent assignment, container discovery, session management,
 * and state reconciliation.
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Supported agent types available for assignment.
 */
export enum AgentType {
  CODER56 = "coder56",
  DB_ADMIN = "db_admin",
  SOC_GOD = "soc_god",
}

// =============================================================================
// Defender (soc_god)
// =============================================================================

export interface DefenderCounters {
  alerts_received: number;
  alerts_dropped_nondefended: number;
  alerts_dropped_duplicate: number;
  plans_generated: number;
  soc_god_sessions_created: number;
  soc_god_sessions_failed: number;
  [k: string]: number;
}

export interface DefenderPolicyEntry {
  enabled: boolean;
  host_ids: string[];
}

export interface DefenderStatus {
  counters: DefenderCounters;
  buffered_alerts: number;
  policy: Record<string, DefenderPolicyEntry>;
  run_id: string;
}

export interface DefenderAlert {
  [k: string]: any;
  received_at?: number;
  run_id?: string;
  topology_id?: string;
}

export interface DefendedHost {
  host_id: string;
  name: string;
  ip: string;
}

export interface PlannerHealth {
  status: string;
  model: string;
  llm_url: string;
  llm_configured: boolean;
  temperature: number;
  max_tokens: number;
}

export interface DefenderPlan {
  target_host: string;
  plan: string;
}

export interface PlannerPlanResponse {
  plans: DefenderPlan[];
  model: string;
  request_id: string;
  created: string;
}

/**
 * Host types that can be created in topologies.
 */
export enum HostType {
  WEB_SERVER = "web-server",
  DATABASE_SERVER = "database-server",
  WORKSTATION = "workstation",
  FIREWALL = "firewall",
  ROUTER = "router",
  SERVER = "server",
  DOMAIN_ADMIN = "domain-admin",
  NORMAL_USER = "normal-user",
}

/**
 * Docker container states.
 */
export enum ContainerState {
  RUNNING = "running",
  STOPPED = "stopped",
  PAUSED = "paused",
  RESTARTING = "restarting",
  EXITED = "exited",
  DEAD = "dead",
  REMOVING = "removing",
  RECREATING = "recreating",
}

/**
 * States for agent assignment lifecycle.
 */
export enum AgentAssignmentState {
  PENDING = "pending",
  ASSIGNED = "assigned",
  RECREATING = "recreating",
  READY = "ready",
  FAILED = "failed",
  REMOVING = "removing",
  REMOVED = "removed",
}

/**
 * OpenCode session states.
 */
export enum SessionState {
  CREATED = "created",
  RUNNING = "running",
  WAITING = "waiting",
  COMPLETED = "completed",
  FAILED = "failed",
  CANCELLED = "cancelled",
  TIMEOUT = "timeout",
}

/**
 * Log entry levels.
 */
export enum LogLevel {
  DEBUG = "DEBUG",
  INFO = "INFO",
  WARNING = "WARNING",
  ERROR = "ERROR",
  CRITICAL = "CRITICAL",
}

/**
 * Reconciliation operation status.
 */
export enum ReconciliationStatus {
  PENDING = "pending",
  RUNNING = "running",
  COMPLETED = "completed",
  FAILED = "failed",
  PARTIAL = "partial",
}

/**
 * Types of events that can be streamed via WebSocket.
 */
export enum EventType {
  AGENT_ASSIGNED = "agent_assigned",
  AGENT_REMOVED = "agent_removed",
  AGENT_READY = "agent_ready",
  AGENT_FAILED = "agent_failed",
  SESSION_CREATED = "session_created",
  SESSION_UPDATED = "session_updated",
  SESSION_COMPLETED = "session_completed",
  SESSION_FAILED = "session_failed",
  CONTAINER_RECREATED = "container_recreated",
  CONTAINER_DISCOVERED = "container_discovered",
  RECONCILIATION_STARTED = "reconciliation_started",
  RECONCILIATION_COMPLETED = "reconciliation_completed",
  LOG_ENTRY = "log_entry",
}

// =============================================================================
// Base Types
// =============================================================================

/**
 * Base interface with timestamp fields.
 */
export interface Timestamped {
  created_at: string;
  updated_at?: string;
}

/**
 * Base interface with ID field.
 */
export interface Identified {
  id: string;
}

// =============================================================================
// Agent Template Types
// =============================================================================

/**
 * Capability description for an agent type.
 */
export interface AgentCapability {
  name: string;
  description: string;
}

/**
 * Template describing an available agent type.
 */
export interface AgentTemplate {
  agent_type: AgentType;
  name: string;
  description: string;
  capabilities: AgentCapability[];
  opencode_image_required: boolean;
  supported_base_images: string[];
}

/**
 * Response containing all available agent templates.
 */
export interface AgentTemplatesResponse {
  agents: Record<AgentType, AgentTemplate>;
}

// =============================================================================
// Agent Assignment Types
// =============================================================================

/**
 * Request to assign an agent to a host.
 */
export interface AgentAssignment {
  topology_id: string;
  network_id: string;
  host_id: string;
  agent_type: AgentType;
  assigned_by?: string;
}

/**
 * Response from agent assignment request.
 */
export interface AgentAssignmentResponse {
  status: AgentAssignmentState;
  message: string;
  topology_id: string;
  network_id: string;
  host_id: string;
  agent_type: AgentType;
  job_id?: string;
  estimated_completion_seconds?: number;
}

// =============================================================================
// Container Types
// =============================================================================

/**
 * Information about a discovered container.
 */
export interface ContainerInfo {
  container_id: string;
  container_name: string;
  topology_id: string;
  network_id: string;
  host_id: string;
  host_name: string;
  host_type: HostType;
  ip_address?: string;
  image: string;
  state: ContainerState;
  current_agents: AgentType[];
  can_assign_agent: boolean;
  opencode_ready: boolean;
  opencode_port?: number;
  labels: Record<string, string>;
}

/**
 * Response from container discovery request.
 */
export interface ContainerDiscoveryResponse {
  containers: ContainerInfo[];
  total_count: number;
  filters_applied: Record<string, any>;
}

// =============================================================================
// Session Types
// =============================================================================

/**
 * Message in an agent session.
 */
export interface SessionMessage {
  id: string;
  timestamp: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  tool_calls?: Record<string, any>[];
  tokens_used?: number;
}

/**
 * Metrics collected during a session.
 */
export interface SessionMetrics {
  total_messages: number;
  total_tokens_used: number;
  estimated_cost?: number;
  execution_time_seconds: number;
  tool_calls_count: number;
}

/**
 * An agent participating in a session's run: the root (lead) session, an
 * opencode child session spawned via the Task tool (coder56_phase,
 * coder56_verifier, ...), or the container's guardrail judge session.
 */
export interface SessionAgentInfo {
  session_id: string;
  label: string;
  title: string;
  parent_id?: string | null;
  depth: number;
  created?: number | null;
  updated?: number | null;
}

/**
 * Information about an OpenCode session.
 */
export interface SessionInfo extends Timestamped {
  session_id: string;
  container_id: string;
  host_id: string;
  agent_type: AgentType;
  state: SessionState;
  messages: SessionMessage[];
  metrics: SessionMetrics;
  last_activity?: string;
  error_message?: string;
}

/**
 * Request to create a new agent session.
 */
export interface SessionCreateRequest {
  container_id: string;
  host_id: string;
  agent_type: AgentType;
  initial_prompt?: string;
  session_metadata?: Record<string, any>;
}

/**
 * Request to send a prompt to an existing session.
 */
export interface SessionPromptRequest {
  prompt: string;
  include_history?: boolean;
  timeout_seconds?: number;
}

// =============================================================================
// Agent State Types
// =============================================================================

/**
 * Persistent state of an agent assignment.
 */
export interface AgentStateAssignment extends Timestamped, Identified {
  container_id: string;
  container_name: string;
  topology_id: string;
  network_id: string;
  host_id: string;
  host_name: string;
  agent_type: AgentType;
  state: AgentAssignmentState;
  assigned_by: string;
  session_id?: string;
  opencode_image: string;
  original_image: string;
  assigned_at: string;
  recreated_at?: string;
  error_message?: string;
}

/**
 * Global agent state (stored in agent_state.json).
 */
export interface AgentState extends Timestamped {
  version: string;
  updated_at: string;
  assignments: AgentStateAssignment[];
  sessions: Record<string, SessionInfo>;
  last_reconciliation_at?: string;
}

// =============================================================================
// Reconciliation Types
// =============================================================================

/**
 * Mismatch detected between desired and actual container state.
 */
export interface ContainerStateMismatch {
  host_id: string;
  container_id: string;
  desired_agents: AgentType[];
  actual_agents: AgentType[];
  desired_image: string;
  actual_image: string;
  mismatch_type: "missing_agents" | "extra_agents" | "wrong_image" | "container_missing";
  action_required: "recreate" | "assign" | "remove" | "ignore";
}

/**
 * Result of a reconciliation operation.
 */
export interface ReconciliationResult extends Timestamped {
  topology_id: string;
  status: ReconciliationStatus;
  containers_checked: number;
  mismatches_found: number;
  containers_reconciled: number;
  failures: string[];
  mismatches: ContainerStateMismatch[];
  duration_seconds: number;
  error_message?: string;
}

/**
 * Current reconciliation status across all topologies.
 */
export interface ReconciliationStatusResponse {
  last_reconciliation_at?: string;
  auto_reconcile_enabled: boolean;
  reconcile_interval_seconds: number;
  recent_results: ReconciliationResult[];
  active_topologies: string[];
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Response from an agent (via OpenCode).
 */
export interface AgentResponse {
  session_id: string;
  agent_type: AgentType;
  timestamp: string;
  status: SessionState;
  content?: string;
  tool_results?: Record<string, any>[];
  error?: string;
  tokens_used?: number;
  execution_time_ms?: number;
}

/**
 * Single log entry from agent activity.
 */
export interface LogEntry extends Timestamped, Identified {
  id: string;
  timestamp: string;
  level: LogLevel;
  agent_type: AgentType;
  session_id: string;
  container_id: string;
  message: string;
  metadata?: Record<string, any>;
}

/**
 * Request to stream agent logs.
 */
export interface LogStreamRequest {
  session_id: string;
  level_filter?: LogLevel;
  since?: string;
  include_tool_calls?: boolean;
}

/**
 * Response containing log entries.
 */
export interface LogStreamResponse {
  session_id: string;
  logs: LogEntry[];
  total_count: number;
  has_more: boolean;
}

// =============================================================================
// Topology Types
// =============================================================================

/**
 * Router configuration from topology.
 */
export interface RouterInfo {
  id: string;
  name: string;
  parent_router_id: string;
  ssh_enabled: boolean;
  username: string;
  password: string;
}

/**
 * Host configuration from topology.
 */
export interface HostInfo {
  id: string;
  name: string;
  type: HostType;
  image: string;
  ssh_enabled: boolean;
  username: string;
  password: string;
  generate_data: boolean;
  data_prompt: string;
  data_content: string;
  agents: AgentType[];
}

/**
 * Network configuration from topology.
 */
export interface NetworkInfo {
  id: string;
  name: string;
  cidr: string;
  internet: boolean;
  router_ids: string[];
  default_router_id: string;
  hosts: HostInfo[];
}

/**
 * Complete topology configuration.
 */
export interface TopologyInfo extends Timestamped {
  id: string;
  name: string;
  version: string;
  routers: RouterInfo[];
  networks: NetworkInfo[];
  router: Record<string, any>;
  infrastructure: Record<string, any>;
}

// =============================================================================
// Additional Topology Types for Dashboard
// =============================================================================

/**
 * Simplified topology for dashboard display.
 * List endpoint returns network_count/host_count/is_running (not full arrays).
 * Detail endpoint returns full networks and routers arrays.
 */
export interface Topology {
  id: string;
  name: string;
  version: string;
  created_at?: string;
  updated_at?: string;
  // List-only summary fields
  network_count?: number;
  host_count?: number;
  is_running?: boolean;
  // Detail-only full data
  networks?: Network[];
  routers?: Router[];
  infrastructure?: Record<string, unknown>;
}

/**
 * Simplified network for dashboard display.
 */
export interface Network {
  id: string;
  name: string;
  cidr: string;
  internet: boolean;
  router_ids?: string[];
  default_router_id?: string;
  hosts?: Host[];
}

/**
 * Simplified router for dashboard display.
 */
export interface Router {
  id: string;
  name: string;
  parent_router_id?: string;
  ssh_enabled?: boolean;
  username?: string;
  password?: string;
}

/**
 * Simplified host for dashboard display.
 */
export interface Host {
  id: string;
  name: string;
  type: string;
  image: string;
  ssh_enabled?: boolean;
  username?: string;
  password?: string;
  agents?: string[];
  /** Opt host into the guardrail/gate. undefined = auto (armed iff a
   * guarded agent — coder56/soc_god — is present on the host). */
  guardrail_enabled?: boolean;
  /** Run coder56 with its independent verifier. undefined = enabled. */
  coder56_verifier_enabled?: boolean;
  generate_data?: boolean;
  data_prompt?: string;
  data_content?: string;
}

// =============================================================================
// API Response Wrappers
// =============================================================================

/**
 * Standard API response wrapper.
 */
export interface APIResponse<T = any> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

/**
 * Status of a background job.
 */
export type JobType = "agent_assign" | "agent_remove" | "container_recreate" | "reconcile";
export type JobStatusType = "queued" | "running" | "completed" | "failed";

export interface JobStatus {
  job_id: string;
  job_type: JobType;
  status: JobStatusType;
  progress: number;
  message: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

// =============================================================================
// Health and Metrics Types
// =============================================================================

/**
 * Health status of a single component.
 */
export type ComponentHealthStatus = "healthy" | "degraded" | "unhealthy";

export interface ComponentHealth {
  status: ComponentHealthStatus;
  ready?: boolean;
  error?: string;
  container_count?: number;
  assignment_count?: number;
  active_connections?: number;
}

/**
 * Health check response.
 */
export interface HealthResponse {
  status: ComponentHealthStatus;
  timestamp: string;
  components: Record<string, ComponentHealth>;
}

/**
 * Agent-related metrics.
 */
export interface AgentMetrics {
  total_assignments: number;
  by_topology: Record<string, number>;
  by_type: Record<string, number>;
  by_status: Record<string, number>;
}

/**
 * Container-related metrics.
 */
export interface ContainerMetrics {
  total: number;
  by_state: Record<string, number>;
}

/**
 * Session-related metrics.
 */
export interface SessionMetricsDashboard {
  total: number;
  by_status: Record<string, number>;
}

/**
 * WebSocket-related metrics.
 */
export interface WebSocketMetrics {
  active_connections: number;
}

/**
 * Background task-related metrics.
 */
export interface BackgroundTaskMetrics {
  reconcile_running: boolean;
  image_build_running: boolean;
  reconcile_interval_seconds: number;
  image_build_interval_seconds: number;
}

/**
 * System metrics response.
 */
export interface MetricsResponse {
  timestamp: string;
  agents: AgentMetrics;
  containers: ContainerMetrics;
  sessions: SessionMetricsDashboard;
  websocket: WebSocketMetrics;
  background_tasks: BackgroundTaskMetrics;
}

// =============================================================================
// Event Types (for WebSocket streaming)
// =============================================================================

/**
 * Event for streaming via WebSocket.
 */
export interface AgentEvent {
  event_type: EventType;
  timestamp: string;
  event_id: string;
  topology_id?: string;
  host_id?: string;
  agent_type?: AgentType;
  session_id?: string;
  data: Record<string, any>;
}

// =============================================================================
// Additional API Types
// =============================================================================

/**
 * Host status in agent assignment context.
 */
export type AgentHostStatus = "available" | "assigned" | "unavailable" | "error";

/**
 * Job status response wrapper.
 */
export interface JobStatusResponse {
  job_id: string;
  status: JobStatusType;
  message: string;
  progress: number;
  error?: string;
}

/**
 * Validation response for API requests.
 */
export interface ValidationResponse {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
}

/**
 * Detailed container information response.
 */
export interface ContainerDetailResponse {
  container: ContainerInfo;
  agents: AgentType[];
  can_assign: boolean;
  opencode_ready: boolean;
}

/**
 * API endpoints summary.
 */
export interface EndpointsSummary {
  base: string;
  endpoints: Record<string, string>;
  version: string;
}

/**
 * Container statistics response.
 */
export interface ContainerStatsResponse {
  container_id: string;
  cpu_percent: number;
  memory_usage_mb: number;
  memory_limit_mb: number;
  network_rx_bytes: number;
  network_tx_bytes: number;
  block_read_bytes: number;
  block_write_bytes: number;
}

// NOTE: the canonical WebSocketMessage used by the HTTP/WS client lives in api.ts;
// the trident-era duplicate that lived here was removed during type consolidation.

/* ── Container status types ─────────────────────────────────────── */

export type TridentContainerState =
  | 'running'
  | 'stopped'
  | 'restarting'
  | 'paused'
  | 'exited'
  | 'dead'
  | 'unknown';

export interface TridentContainerInfo {
  id: string;
  name: string;
  image: string;
  state: TridentContainerState;
  status: string;
  health: string | null;
  networks: string[];
  ip_addresses: Record<string, string>;
}

/* ── Topology ──────────────────────────────────────────────────── */

export type NodeType = 'router' | 'server' | 'host' | 'attacker' | 'defender' | 'dashboard';

export interface TopologyNode {
  id: string;
  label: string;
  type: NodeType;
  ips: string[];
  networks: string[];
  services: string[];
  container: string;
  state: TridentContainerState;
  position: { x: number; y: number };
}

export interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  animated: boolean;
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

/* ── OpenCode ──────────────────────────────────────────────────── */

export interface MessagePart {
  type: string;
  text?: string;
  tool?: string;
  time?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface TridentSessionMessage {
  info?: {
    sessionID?: string;
    role?: string;
    time?: { created?: number; completed?: number };
    tokens?: { input?: number; output?: number; reasoning?: number };
    cost?: number;
    finish?: string;
  };
  parts: MessagePart[];
}

export interface SessionsMap {
  [sessionId: string]: string;
}

/* ── Alerts ────────────────────────────────────────────────────── */

export interface AlertEntry {
  timestamp?: string;
  run_id?: string;
  [key: string]: unknown;
}

/* ── PCAPs ─────────────────────────────────────────────────────── */

export interface PcapFile {
  filename: string;
  path: string;
  size_bytes: number;
  modified: string;
  slips_checked?: boolean;
}

/* ── Runs ──────────────────────────────────────────────────────── */

export interface RunInfo {
  run_id: string;
  path: string;
  is_current: boolean;
  created: string;
  has_pcaps: boolean;
  has_alerts: boolean;
}

/* ── Timeline ──────────────────────────────────────────────────── */

export interface TimelineEntry {
  ts: string;
  level: string;
  msg: string;
  exec?: string;
  data?: Record<string, unknown>;
}

/* ── Health ─────────────────────────────────────────────────────── */

export interface ServiceHealth {
  name: string;
  healthy: boolean;
  detail: string;
}

export interface TridentHealthResponse {
  status: string;
  run_id: string | null;
  timestamp: string;
  services: ServiceHealth[];
}

/* ── WebSocket message types ───────────────────────────────────── */

export interface WsContainersMessage {
  type: 'containers';
  data: TridentContainerInfo[];
}

export interface WsSessionsMessage {
  type: 'sessions';
  host: string;
  data: SessionsMap;
}

export interface WsMessagesMessage {
  type: 'messages';
  host: string;
  session_id: string;
  data: TridentSessionMessage[];
  total: number;
}

export interface OpenCodeStatePayload {
  run_id: string | null;
  updated_at: string;
  sessions: SessionsMap;
  session_sources?: Record<string, string>;
  messages_by_session: Record<string, TridentSessionMessage[]>;
}

export interface WsAlertMessage {
  type: 'alert';
  run_id: string;
  data: AlertEntry;
}

export interface WsTimelineMessage {
  type: 'timeline';
  agent: string;
  data: TimelineEntry;
}

/* ── Replay ─────────────────────────────────────────────────────── */

export interface ReplayEvent {
  timestamp_ms: number;
  source_type: 'timeline' | 'opencode' | 'alert';
  source_file: string;
  ts?: string;
  level?: string;
  msg?: string;
  data?: Record<string, unknown>;
  info?: {
    sessionID?: string;
    role?: string;
    time?: { created?: number; completed?: number };
    tokens?: { input?: number; output?: number; reasoning?: number };
    timestamp?: number;
  };
  parts?: MessagePart[];
  session_id?: string;
  [key: string]: unknown;
}

export interface ReplayState {
  replayId: string | null;
  path: string | null;
  positionMs: number;
  durationMs: number;
  startTimeMs: number;
  endTimeMs: number;
  eventCount: number;
  isPlaying: boolean;
  speed: number;
  events: ReplayEvent[];
  error: string | null;
}

export interface ReplayMetadata {
  replay_id: string;
  path: string;
  start_time_ms: number;
  end_time_ms: number;
  duration_ms: number;
  event_count: number;
  initial_events?: ReplayEvent[];
}

export interface ReplayRunInfo {
  run_id: string;
  path: string;
  is_current: boolean;
  created: string;
}

export interface WsReplayStateMessage {
  type: 'state';
  replay_id: string;
  position_ms: number;
  playing: boolean;
  speed: number;
  duration_ms: number;
  start_time_ms?: number;
  end_time_ms?: number;
}

export interface WsReplayEventsMessage {
  type: 'events';
  events: ReplayEvent[];
}

export interface WsReplayPlaybackCompleteMessage {
  type: 'playback_complete';
}

export interface WsReplayErrorMessage {
  type: 'error';
  message: string;
}

export type WsReplayMessage =
  | WsReplayStateMessage
  | WsReplayEventsMessage
  | WsReplayPlaybackCompleteMessage
  | WsReplayErrorMessage;

/* ── Agent Templates (trident shape) ───────────────────────────────── */

export interface TridentAgentTemplate {
  agent_type: string;
  name: string;
  description: string;
  capabilities: { name: string; description: string }[];
  opencode_image_required: boolean;
  supported_base_images: string[];
}

export interface TridentAgentAssignment {
  topology_id: string;
  network_id: string;
  host_id: string;
  agent_type: string;
  assigned_by?: string;
}
