/**
 * API Client for Agent Manager Plugin
 *
 * Provides axios-based HTTP client and WebSocket connections for all backend endpoints.
 * Handles agent lifecycle, container discovery, session management, and real-time events.
 */

import axios, { AxiosInstance, AxiosResponse, AxiosError } from 'axios';
import type {
  // Agent Types
  AgentType,
  AgentAssignment,
  AgentAssignmentResponse,
  AgentAssignmentState,
  AgentState,
  AgentStateAssignment,
  AgentTemplate,
  AgentTemplatesResponse,

  // Container Types
  ContainerInfo,
  ContainerDiscoveryResponse,
  ContainerState,

  // Session Types
  SessionInfo,
  SessionCreateRequest,
  SessionPromptRequest,
  SessionMessage,
  AgentResponse,
  LogEntry,
  LogStreamResponse,

  // State & Reconciliation
  ReconciliationResult,
  ReconciliationStatusResponse,

  // Health & Metrics
  HealthResponse,
  MetricsResponse,

  // API Wrapper
  APIResponse,
  JobStatus,

  // Events
  AgentEvent,
  EventType,

  // Timeline / streaming (formerly in trident.ts)
  TimelineEntry,

  // Models for endpoints not in types.ts
  AgentHostStatus,
  JobStatusResponse,
  ValidationResponse,
  ContainerDetailResponse,
  EndpointsSummary,
  ContainerStatsResponse,

  // Topology Types
  Topology,
  Network,
  Host,

  // Defender Types
  DefenderStatus,
  DefenderAlert,
  DefendedHost,
  PlannerHealth,
  PlannerPlanResponse,
} from './types';
import { pluginWebSocketUrl } from './plugin-url';

// =============================================================================
// Configuration
// =============================================================================

// Use empty string so axios makes same-origin requests (works for any host).
// Falls back to localhost:8000 only if the env var is truly absent (undefined).
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '.';

// =============================================================================
// Error Types
// =============================================================================

export class APIError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public response?: any
  ) {
    super(message);
    this.name = 'APIError';
  }
}

export class WebSocketError extends Error {
  constructor(message: string, public event?: MessageEvent) {
    super(message);
    this.name = 'WebSocketError';
  }
}

// =============================================================================
// Axios Instance
// =============================================================================

const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Request interceptor
apiClient.interceptors.request.use(
  (config) => {
    console.log('[API Request]', config.method?.toUpperCase(), config.url, config.data);
    // Add auth token if available
    const token = localStorage.getItem('auth_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('[API Request Error]', error);
    return Promise.reject(error);
  }
);

// Response interceptor
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    console.log('[API Response]', response.status, response.config.url, response.data);
    return response;
  },
  (error: AxiosError) => {
    console.error('[API Error]', {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      url: error.config?.url,
      requestURL: error.request?.responseURL,
      hasResponse: !!error.response,
      hasRequest: !!error.request
    });
    if (error.response) {
      // Server responded with error status
      const message = (error.response.data as any)?.message || error.message;
      throw new APIError(message, error.response.status, error.response.data);
    } else if (error.request) {
      // Request made but no response
      throw new APIError('No response from server. Please check your connection.');
    } else {
      // Request setup error
      throw new APIError(error.message);
    }
  }
);

// =============================================================================
// Topology Management APIs
// =============================================================================

/**
 * Get all topologies from network-topology plugin
 */
export async function getTopologies(): Promise<{ topologies: Topology[] }> {
  const response = await apiClient.get<{ topologies: Topology[] }>('/api/topologies');
  return response.data;
}

/**
 * Get a specific topology by ID
 */
export async function getTopology(topologyId: string): Promise<Topology> {
  const response = await apiClient.get<Topology>(`/api/topologies/${topologyId}`);
  return response.data;
}

/**
 * Start a topology (launch docker containers)
 *
 * The backend runs start asynchronously in the topology plugin and returns a
 * ``job_id``; poll it via {@link getTopologyJob} to learn whether the start
 * actually succeeded or failed (e.g. a subnet-collision at docker-compose up).
 */
export async function startTopology(topologyId: string): Promise<{ message: string; job_id?: string | null }> {
  const response = await apiClient.post<{ message: string; job_id?: string | null }>(`/api/topologies/${topologyId}/start`);
  return response.data;
}

/**
 * Poll a start/stop background job. Mirrors the topology plugin's own
 * waitForJob(): status is 'running' | 'completed' | 'failed'; on failure
 * ``error`` holds the underlying message (e.g. docker-compose stderr).
 */
export async function getTopologyJob(
  topologyId: string,
  jobId: string,
): Promise<{ id?: string; status: string; result?: unknown; error?: string }> {
  const response = await apiClient.get<{ id?: string; status: string; result?: unknown; error?: string }>(
    `/api/topologies/${topologyId}/jobs/${jobId}`,
  );
  return response.data;
}

/**
 * Stop a topology (stop docker containers)
 */
export async function stopTopology(topologyId: string): Promise<{ message: string }> {
  const response = await apiClient.post<{ message: string }>(`/api/topologies/${topologyId}/stop`);
  return response.data;
}

/**
 * Save updated topology (agent assignments per host) back to the network-topology plugin.
 * Only sends the networks array — the backend merges it with the full topology to preserve
 * firewall rules and infrastructure settings.
 */
export async function saveTopology(topologyId: string, networks: Network[]): Promise<Topology> {
  const response = await apiClient.put<Topology>(`/api/topologies/${topologyId}`, { networks });
  return response.data;
}

/**
 * Persist coder56's verifier mode for one host and, by default, apply it by
 * regenerating/restarting the changed topology container.
 */
export async function setCoder56Verifier(
  topologyId: string,
  hostId: string,
  enabled: boolean,
  restart = true,
): Promise<{
  topology_id: string;
  host_id: string;
  enabled: boolean;
  changed: boolean;
  restarting: boolean;
  job_id?: string | null;
  message: string;
}> {
  const response = await apiClient.put(
    `/api/topologies/${topologyId}/hosts/${hostId}/coder56-verifier`,
    { enabled, restart },
  );
  return response.data;
}

/**
 * Create a brand-new topology. Backend forwards to the plugin, which generates a
 * fresh id (slugified name + uuid suffix). Minimal body:
 * { name, networks: [{ name, hosts: [{ name }] }] } — the plugin defaults the rest.
 */
export async function createTopology(payload: { name: string; networks: Network[] }): Promise<Topology> {
  const response = await apiClient.post<Topology>('/api/topologies', payload);
  return response.data;
}

// =============================================================================
// Agent Management APIs
// =============================================================================

/**
 * Get all available agent templates
 */
export async function getAgentTemplates(): Promise<AgentTemplatesResponse> {
  const response = await apiClient.get<AgentTemplatesResponse>('/api/agents/templates');
  return response.data;
}

/**
 * Get a specific agent template by type
 */
export async function getAgentTemplate(agentType: AgentType): Promise<AgentTemplate> {
  const response = await apiClient.get<AgentTemplate>(`/api/agents/templates/${agentType}`);
  return response.data;
}

/**
 * Assign an agent to a host (returns immediately with job_id)
 */
export async function assignAgent(assignment: AgentAssignment): Promise<AgentAssignmentResponse> {
  const response = await apiClient.post<AgentAssignmentResponse>('/api/agents/assign', assignment);
  return response.data;
}

/**
 * Remove an agent from a host (returns immediately with job_id)
 */
export async function removeAgent(
  topologyId: string,
  hostId: string,
  agentType: AgentType,
  networkId: string
): Promise<AgentAssignmentResponse> {
  const response = await apiClient.delete<AgentAssignmentResponse>(
    `/api/agents/${topologyId}/${hostId}/${agentType}`,
    { params: { network_id: networkId } }
  );
  return response.data;
}

/**
 * Get global agent state
 */
export async function getAgentState(statePath?: string): Promise<AgentState> {
  const params = statePath ? { state_path: statePath } : {};
  const response = await apiClient.get<AgentState>('/api/agents/state', { params });
  return response.data;
}

/**
 * Get all agent assignments (optionally filtered)
 */
export async function getAgentAssignments(filters?: {
  topologyId?: string;
  hostId?: string;
  statePath?: string;
}): Promise<AgentStateAssignment[]> {
  const params: Record<string, string> = {};
  if (filters?.topologyId) params.topology_id = filters.topologyId;
  if (filters?.hostId) params.host_id = filters.hostId;
  if (filters?.statePath) params.state_path = filters.statePath;

  const response = await apiClient.get<AgentStateAssignment[]>('/api/agents/assignments', { params });
  return response.data;
}

/**
 * Get agent status for a specific host
 */
export async function getHostStatus(
  topologyId: string,
  hostId: string,
  networkId: string
): Promise<AgentHostStatus> {
  const response = await apiClient.get<AgentHostStatus>(
    `/api/agents/status/${topologyId}/${hostId}`,
    { params: { network_id: networkId } }
  );
  return response.data;
}

/**
 * Get status of a background job
 */
export async function getJobStatus(jobId: string): Promise<JobStatusResponse> {
  const response = await apiClient.get<JobStatusResponse>(`/api/agents/jobs/${jobId}`);
  return response.data;
}

/**
 * Validate an agent assignment before attempting
 */
export async function validateAssignment(assignment: AgentAssignment): Promise<ValidationResponse> {
  const response = await apiClient.post<ValidationResponse>('/api/agents/validate', assignment);
  return response.data;
}

/**
 * Get reconciliation status
 */
export async function getReconciliationStatus(): Promise<ReconciliationStatusResponse> {
  const response = await apiClient.get<ReconciliationStatusResponse>('/api/agents/reconciliation/status');
  return response.data;
}

/**
 * Health check for agents service
 */
export async function getAgentsHealth(): Promise<{ status: string; version: string; supported_agents: string[] }> {
  const response = await apiClient.get('/api/agents/health');
  return response.data;
}

// =============================================================================
// Container Discovery APIs
// =============================================================================

/**
 * Discover containers with comprehensive filtering
 */
export async function discoverContainers(filters?: {
  topologyId?: string;
  networkId?: string;
  hostId?: string;
  state?: ContainerState;
  hasAgents?: boolean;
  hostType?: string;
  includeStopped?: boolean;
}): Promise<ContainerDiscoveryResponse> {
  const params: Record<string, any> = {};
  if (filters?.topologyId) params.topology_id = filters.topologyId;
  if (filters?.networkId) params.network_id = filters.networkId;
  if (filters?.hostId) params.host_id = filters.hostId;
  if (filters?.state) params.state = filters.state;
  if (filters?.hasAgents !== undefined) params.has_agents = filters.hasAgents;
  if (filters?.hostType) params.host_type = filters.hostType;
  if (filters?.includeStopped !== undefined) params.include_stopped = filters.includeStopped;

  const response = await apiClient.get<ContainerDiscoveryResponse>('/api/containers/discover', { params });
  return response.data;
}

/**
 * Get detailed container info by container ID
 */
export async function getContainerDetails(containerId: string): Promise<ContainerDetailResponse> {
  const response = await apiClient.get<ContainerDetailResponse>(`/api/containers/${containerId}`);
  return response.data;
}

/**
 * Get container by topology and host ID
 */
export async function getContainerByHost(
  topologyId: string,
  hostId: string
): Promise<ContainerDetailResponse> {
  const response = await apiClient.get<ContainerDetailResponse>(
    `/api/containers/by-host/${topologyId}/${hostId}`
  );
  return response.data;
}

/**
 * Get container statistics for a topology
 */
export async function getContainerStats(topologyId: string): Promise<ContainerStatsResponse> {
  const response = await apiClient.get<ContainerStatsResponse>(`/api/containers/stats/${topologyId}`);
  return response.data;
}

/**
 * List all SCL topology containers. Backend alias of /discover (same shape as
 * {@link discoverContainers}); used by the container status bar.
 */
export async function getContainers(): Promise<ContainerDiscoveryResponse> {
  const response = await apiClient.get<ContainerDiscoveryResponse>('/api/containers');
  return response.data;
}

// =============================================================================
// Session Management APIs
// =============================================================================

/**
 * List all sessions with optional filtering
 */
export async function listSessions(filters?: {
  limit?: number;
  offset?: number;
  statusFilter?: string;
}): Promise<SessionInfo[]> {
  const params: Record<string, any> = {};
  if (filters?.limit) params.limit = filters.limit;
  if (filters?.offset) params.offset = filters.offset;
  if (filters?.statusFilter) params.status_filter = filters.statusFilter;

  const response = await apiClient.get<SessionInfo[]>('/api/sessions/list', { params });
  return response.data;
}

/**
 * Get session info by ID
 */
export async function getSession(sessionId: string): Promise<SessionInfo> {
  const response = await apiClient.get<SessionInfo>(`/api/sessions/${sessionId}`);
  return response.data;
}

/**
 * Get session messages
 */
export async function getSessionMessages(
  sessionId: string,
  limit: number = 100,
  offset: number = 0
): Promise<SessionMessage[]> {
  const response = await apiClient.get<SessionMessage[]>(`/api/sessions/${sessionId}/messages`, {
    params: { limit, offset }
  });
  return response.data;
}

/**
 * Create a new session
 */
export async function createSession(request: SessionCreateRequest): Promise<SessionInfo> {
  // The backend waits for the initial agent turn (up to 120 seconds). Do not
  // apply the client's 30-second default to this intentionally long request.
  const response = await apiClient.post<SessionInfo>('/api/sessions', request, {
    timeout: 150000,
  });
  return response.data;
}

/**
 * Send a prompt to a session
 */
export async function sendPrompt(
  sessionId: string,
  request: SessionPromptRequest
): Promise<AgentResponse> {
  const response = await apiClient.post<AgentResponse>(
    `/api/sessions/${sessionId}/prompt`,
    request,
    { timeout: 150000 }
  );
  return response.data;
}

/**
 * Delete a session
 */
export async function deleteSession(sessionId: string): Promise<{ message: string }> {
  const response = await apiClient.delete<{ message: string }>(`/api/sessions/${sessionId}`);
  return response.data;
}

/**
 * Get session logs
 */
export async function getSessionLogs(
  sessionId: string,
  filters?: {
    levelFilter?: string;
    since?: string;
    includeToolCalls?: boolean;
  }
): Promise<LogStreamResponse> {
  const params: Record<string, any> = {};
  if (filters?.levelFilter) params.level_filter = filters.levelFilter;
  if (filters?.since) params.since = filters.since;
  if (filters?.includeToolCalls !== undefined) params.include_tool_calls = filters.includeToolCalls;

  const response = await apiClient.get<LogStreamResponse>(`/api/sessions/${sessionId}/logs`, { params });
  return response.data;
}

// =============================================================================
// Defender (soc_god) APIs
// =============================================================================

/** Defender status: counters, buffered alerts, per-topology policy. */
export async function getDefenderStatus(): Promise<DefenderStatus> {
  const response = await apiClient.get<DefenderStatus>('/api/defender/status');
  return response.data;
}

/** Enable/disable the defender for a topology and set its defended hosts. */
export async function enableDefender(
  topologyId: string,
  hostIds: string[],
  enabled: boolean
): Promise<{ status: string; topology_id: string; defended: any }> {
  const response = await apiClient.post('/api/defender/enable', {
    topology_id: topologyId,
    host_ids: hostIds,
    enabled,
  });
  return response.data;
}

/** Ingest a raw SLIPS alert into the defender work-queue. */
export async function ingestDefenderAlert(
  alert: Record<string, any>,
  topologyId?: string
): Promise<{ status: string; run_id: string; buffered_alerts: number }> {
  const response = await apiClient.post('/api/defender/alerts', alert, {
    params: topologyId ? { topology_id: topologyId } : {},
  });
  return response.data;
}

/** Recent buffered alerts (for the dashboard feed). */
export async function getRecentAlerts(
  limit = 50
): Promise<{ alerts: DefenderAlert[]; buffered: number }> {
  const response = await apiClient.get('/api/defender/alerts/recent', { params: { limit } });
  return response.data;
}

/** Defended hosts for a topology with their live IPs. */
export async function getDefendedHosts(
  topologyId: string
): Promise<{ topology_id: string; hosts: DefendedHost[] }> {
  const response = await apiClient.get(`/api/defender/defended-hosts/${topologyId}`);
  return response.data;
}

/** Planner config/health snapshot. */
export async function getPlannerHealth(): Promise<PlannerHealth> {
  const response = await apiClient.get<PlannerHealth>('/api/defender/planner/healthz');
  return response.data;
}

/** Generate a 5-field incident-response plan for an alert + target host. */
export async function planDefender(
  alert: string,
  targetHost?: string,
  topologyId?: string
): Promise<PlannerPlanResponse> {
  const response = await apiClient.post<PlannerPlanResponse>('/api/defender/planner/plan', {
    alert,
    target_host: targetHost,
    topology_id: topologyId,
  });
  return response.data;
}

// =============================================================================
// Timeline APIs
// =============================================================================

/**
 * Live agent timeline. Backed by the timeline_compat router; response carries an
 * `entries` array. `runId` optionally scopes to a replay run.
 */
export async function getTimeline(
  agent: string,
  runId?: string,
): Promise<{ entries: TimelineEntry[] }> {
  const response = await apiClient.get<{ entries: TimelineEntry[] }>(
    `/api/timeline/${agent}`,
    { params: runId ? { run_id: runId } : {} },
  );
  return response.data;
}

// =============================================================================
// WebSocket Connection Manager
// =============================================================================

export interface WebSocketMessage {
  type: string;
  timestamp?: string;
  data?: Record<string, any>;
}

export interface WebSocketCallbacks {
  onMessage?: (message: Record<string, unknown>) => void;
  onError?: (error: WebSocketError) => void;
  onOpen?: (event: Event) => void;
  onClose?: (event: CloseEvent) => void;
  onReconnecting?: (attempt: number) => void;
  onReconnected?: (attempt: number) => void;
}

export class AgentWebSocket {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  private callbacks: WebSocketCallbacks = {};
  private manualClose = false;
  private pingInterval: ReturnType<typeof setInterval> | null = null;

  constructor(url: string, callbacks?: WebSocketCallbacks) {
    this.url = url;
    if (callbacks) {
      this.callbacks = callbacks;
    }
  }

  /**
   * Connect to WebSocket server
   */
  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    this.manualClose = false;

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = (event) => {
        this.reconnectAttempts = 0;
        this.startPing();
        this.callbacks.onOpen?.(event);
      };

      this.ws.onmessage = (event) => {
        try {
          // Forward every parsed message verbatim. Consumers (agent-event feeds,
          // defender event feeds) filter by shape themselves — the prior code only
          // forwarded AgentEvent-shaped messages and silently dropped the rest.
          const message = JSON.parse(event.data) as Record<string, unknown>;
          this.callbacks.onMessage?.(message);
        } catch (error) {
          this.callbacks.onError?.(
            new WebSocketError('Failed to parse WebSocket message', event)
          );
        }
      };

      this.ws.onerror = (event) => {
        this.callbacks.onError?.(new WebSocketError('WebSocket error occurred'));
      };

      this.ws.onclose = (event) => {
        this.stopPing();
        this.callbacks.onClose?.(event);

        if (!this.manualClose && this.reconnectAttempts < this.maxReconnectAttempts) {
          this.scheduleReconnect();
        }
      };
    } catch (error) {
      this.callbacks.onError?.(
        new WebSocketError(`Failed to connect: ${error instanceof Error ? error.message : 'Unknown error'}`)
      );
    }
  }

  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    this.manualClose = true;
    this.stopPing();

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Send a message through WebSocket
   */
  send(message: WebSocketMessage): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      throw new WebSocketError('WebSocket is not connected');
    }
  }

  /**
   * Subscribe to specific events
   */
  subscribe(events: string[]): void {
    this.send({
      type: 'subscribe',
      timestamp: new Date().toISOString(),
      data: { events }
    });
  }

  /**
   * Send ping message
   */
  ping(): void {
    this.send({ type: 'ping' });
  }

  /**
   * Schedule reconnection attempt
   */
  private scheduleReconnect(): void {
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    this.callbacks.onReconnecting?.(this.reconnectAttempts);

    this.reconnectTimeout = setTimeout(() => {
      this.callbacks.onReconnected?.(this.reconnectAttempts);
      this.connect();
    }, delay);
  }

  /**
   * Start periodic ping to keep connection alive
   */
  private startPing(): void {
    this.pingInterval = setInterval(() => {
      this.ping();
    }, 30000); // Ping every 30 seconds
  }

  /**
   * Stop periodic ping
   */
  private stopPing(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  /**
   * Get connection state
   */
  get readyState(): number {
    return this.ws?.readyState ?? WebSocket.CLOSED;
  }

  /**
   * Check if connected
   */
  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

/**
 * Create a WebSocket connection for events
 */
export function createEventWebSocket(callbacks?: WebSocketCallbacks): AgentWebSocket {
  const url = pluginWebSocketUrl('/ws/events');
  return new AgentWebSocket(url, callbacks);
}

/**
 * Create a WebSocket connection for a specific session
 */
export function createSessionWebSocket(
  sessionId: string,
  callbacks?: WebSocketCallbacks
): AgentWebSocket {
  const url = pluginWebSocketUrl(`/api/sessions/ws/${sessionId}`);
  return new AgentWebSocket(url, callbacks);
}

// =============================================================================
// Health & Metrics APIs
// =============================================================================

/**
 * Get system health status
 */
export async function getHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>('/health');
  return response.data;
}

/**
 * Get system metrics
 */
export async function getMetrics(): Promise<MetricsResponse> {
  const response = await apiClient.get<MetricsResponse>('/metrics');
  return response.data;
}

/**
 * Get API root information
 */
export async function getApiInfo(): Promise<APIResponse<{ docs: string; redoc: string; websocket: string }>> {
  const response = await apiClient.get<APIResponse>('/');
  return response.data;
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert API error to user-friendly message
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof APIError) {
    return error.message;
  }
  if (error instanceof WebSocketError) {
    return error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'An unknown error occurred';
}

/**
 * Check if error is a network error
 */
export function isNetworkError(error: unknown): boolean {
  return error instanceof APIError && !error.statusCode;
}

/**
 * Check if error is a timeout
 */
export function isTimeoutError(error: unknown): boolean {
  return error instanceof APIError && error.statusCode === 408;
}

/**
 * Create a query string from parameters
 */
export function buildQueryString(params: Record<string, any>): string {
  const searchParams = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      searchParams.append(key, String(value));
    }
  });
  return searchParams.toString();
}

// =============================================================================
// Re-Export Types for Convenience
// =============================================================================

export type {
  AgentType,
  AgentAssignment,
  AgentAssignmentResponse,
  AgentAssignmentState,
  AgentState,
  AgentStateAssignment,
  AgentTemplate,
  AgentTemplatesResponse,
  ContainerInfo,
  ContainerDiscoveryResponse,
  ContainerState,
  SessionInfo,
  SessionCreateRequest,
  SessionPromptRequest,
  SessionMessage,
  AgentResponse,
  LogEntry,
  LogStreamResponse,
  ReconciliationResult,
  ReconciliationStatusResponse,
  HealthResponse,
  MetricsResponse,
  APIResponse,
  JobStatus,
  AgentEvent,
  EventType,
  AgentHostStatus,
  JobStatusResponse,
  ValidationResponse,
  ContainerDetailResponse,
  EndpointsSummary,
  ContainerStatsResponse,
  Topology,
  Network,
  Host,
  DefenderStatus,
  DefenderAlert,
  DefendedHost,
  PlannerHealth,
  PlannerPlanResponse,
};

// =============================================================================
// API Client Instance (for direct use)
// =============================================================================

export { apiClient as httpClient };

export default {
  // Topology Management
  getTopologies,
  getTopology,
  startTopology,
  stopTopology,
  saveTopology,
  setCoder56Verifier,
  createTopology,
  getTopologyJob,

  // Agent Management
  getAgentTemplates,
  getAgentTemplate,
  assignAgent,
  removeAgent,
  getAgentState,
  getAgentAssignments,
  getHostStatus,
  getJobStatus,
  validateAssignment,
  getReconciliationStatus,
  getAgentsHealth,

  // Container Discovery
  discoverContainers,
  getContainerDetails,
  getContainerByHost,
  getContainerStats,
  getContainers,

  // Session Management
  listSessions,
  getSession,
  getSessionMessages,
  createSession,
  sendPrompt,
  deleteSession,
  getSessionLogs,

  // WebSocket
  createEventWebSocket,
  createSessionWebSocket,

  // Health & Metrics
  getHealth,
  getMetrics,
  getApiInfo,

  // Utilities
  getErrorMessage,
  isNetworkError,
  isTimeoutError,
  buildQueryString,

  // Defender
  getDefenderStatus,
  enableDefender,
  ingestDefenderAlert,
  getRecentAlerts,
  getDefendedHosts,
  getPlannerHealth,
  planDefender,

  // Timeline
  getTimeline,

  // HTTP Client
  httpClient: apiClient,
};
