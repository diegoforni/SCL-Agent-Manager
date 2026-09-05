import { useState, useEffect, useMemo } from 'react';
import { Radio, MessageSquare, PlayCircle, Loader2, Shield } from 'lucide-react';
import { SessionStream } from '@/components/SessionStream';
import { ReplayAgentView, ReplayHeader } from '@/components/ReplayAgentView';
import { useReplayContext } from '@/contexts/ReplayContext';
import api, { APIError } from '@/api';
import type { AgentStateAssignment, SessionMessage, SessionAgentInfo, AgentTemplate, SessionInfo, AgentType, ContainerInfo, Topology, Host } from '@/types';
import { ContainerState } from '@/types';

// Agent Panel Component
function AgentPanel({
  assignment,
  template,
  sessions,
  isGuarded,
  verifierEnabled,
  verifierApplying,
  onToggleVerifier,
}: {
  assignment: AgentStateAssignment;
  template?: AgentTemplate;
  sessions: SessionInfo[];
  isGuarded?: boolean;
  verifierEnabled?: boolean;
  verifierApplying?: boolean;
  onToggleVerifier?: () => void;
}) {
  const [activeSession, setActiveSession] = useState<SessionInfo | null>(null);
  const [messages, setMessages] = useState<SessionMessage[]>([]);
  const [goal, setGoal] = useState('');
  const [isStarting, setIsStarting] = useState(false);
  // Sub-agent view (coder56): the lead session spawns coder56_phase /
  // coder56_verifier children that only exist inside opencode. `agents` is the
  // discovered tree; `followLatest` auto-tracks the most recently active agent
  // until the operator pins one explicitly.
  const [agents, setAgents] = useState<SessionAgentInfo[]>([]);
  const [pinnedAgentId, setPinnedAgentId] = useState<string | null>(null);
  const isCoder56 = assignment.agent_type === 'coder56';

  const mySessions = useMemo(() => sessions.filter(s =>
    s.container_id === assignment.container_id &&
    s.agent_type === assignment.agent_type
  ), [sessions, assignment.container_id, assignment.agent_type]);

  // Keep the selected session valid as the page-level session poll updates.
  useEffect(() => {
    setActiveSession(current => {
      if (current && mySessions.some(s => s.session_id === current.session_id)) {
        return current;
      }
      return mySessions[0] ?? null;
    });
  }, [mySessions]);

  // Discover the session's agent tree (lead + Task-tool subagents + guardrail).
  // Polled slowly — it only changes when a subagent is spawned or finishes.
  useEffect(() => {
    if (!activeSession || !isCoder56) {
      setAgents([]);
      return;
    }

    let cancelled = false;
    let timer: number | undefined;

    const pollAgents = async () => {
      try {
        const next = await api.getSessionAgents(activeSession.session_id);
        if (!cancelled) setAgents(next);
      } catch (err) {
        console.error("Error polling session agents", err);
      } finally {
        if (!cancelled) {
          timer = window.setTimeout(pollAgents, 10000);
        }
      }
    };

    pollAgents();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeSession?.session_id, isCoder56]);

  const latestAgentId = useMemo(() => {
    if (!activeSession || agents.length === 0) return activeSession?.session_id ?? null;
    const withTimes = agents.filter(a => typeof a.updated === 'number');
    const newest = withTimes.reduce((acc, a) => (a.updated! > acc.updated! ? a : acc), withTimes[0]);
    return newest?.session_id ?? activeSession.session_id;
  }, [agents, activeSession?.session_id]);

  const selectedAgentId = pinnedAgentId && agents.some(a => a.session_id === pinnedAgentId)
    ? pinnedAgentId
    : latestAgentId;
  const selectedAgent = agents.find(a => a.session_id === selectedAgentId);

  // Poll only this panel's active session messages, scheduling the next poll
  // after the previous request finishes so slow requests never overlap.
  useEffect(() => {
    if (!activeSession) {
      setMessages([]);
      return;
    }

    let cancelled = false;
    let timer: number | undefined;

    const pollMessages = async () => {
      try {
        const rootId = activeSession.session_id;
        const msgs = (selectedAgentId && selectedAgentId !== rootId)
          ? await api.getSessionAgentMessages(rootId, selectedAgentId)
          : await api.getSessionMessages(rootId);
        if (!cancelled) {
          setMessages(msgs);
        }
      } catch (err) {
        console.error("Error polling session data", err);
      } finally {
        if (!cancelled) {
          timer = window.setTimeout(pollMessages, 3000);
        }
      }
    };

    pollMessages();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [activeSession?.session_id, selectedAgentId]);

  const handleStartGoal = async () => {
    if (!goal.trim()) return;
    setIsStarting(true);
    try {
      console.log('[DEBUG] Creating session with:', {
        container_id: assignment.container_id,
        host_id: assignment.host_id,
        agent_type: assignment.agent_type,
        initial_prompt: goal
      });
      const newSession = await api.createSession({
        container_id: assignment.container_id,
        host_id: assignment.host_id,
        agent_type: assignment.agent_type as AgentType,
        initial_prompt: goal
      });
      console.log('[DEBUG] Session created:', newSession);
      setActiveSession(newSession);
      setGoal('');
      setMessages([]);
    } catch (err) {
      console.error("Failed to start goal", err);
      console.error('[DEBUG] Error details:', {
        message: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined,
        isAPIError: err instanceof APIError,
        statusCode: err instanceof APIError ? err.statusCode : undefined,
        response: err instanceof APIError ? err.response : undefined
      });
    } finally {
      setIsStarting(false);
    }
  };

  const label = template?.name || assignment.agent_type;
  const desc = template?.description || 'Agent';

  return (
    <div className="card flex flex-col h-[500px]">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio size={16} className="text-trident-accent" />
          <h3 className="font-heading text-lg font-bold text-trident-accent truncate" title={`${label} on ${assignment.host_name}`}>{label} on {assignment.host_name}</h3>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {isGuarded && (
            <span className="badge badge-warning flex items-center gap-1" title="Guarded by ClawKeeper (bash commands audited)">
              <Shield size={12} />
              guarded
            </span>
          )}
          {assignment.agent_type === 'coder56' && (
            <label
              title="Independent finding verifier. Turning this off restores legacy single-agent execution and restarts the changed topology container."
              className={`badge flex items-center gap-1 cursor-pointer select-none ${
                verifierEnabled ? 'badge-info' : 'bg-trident-border/40 text-trident-muted'
              }`}
            >
              {verifierApplying ? (
                <Loader2 size={12} className="animate-spin" />
              ) : (
                <input
                  type="checkbox"
                  checked={verifierEnabled ?? true}
                  onChange={onToggleVerifier}
                  className="accent-violet-500"
                />
              )}
              verifier {verifierEnabled ? 'on' : 'off'}
            </label>
          )}
          <span className={`badge ${assignment.state === 'ready' ? 'badge-success' : assignment.state === 'failed' ? 'badge-danger' : 'badge-info'}`}>
            {assignment.state}
          </span>
        </div>
      </div>

      <p className="mb-3 text-xs text-trident-muted line-clamp-2" title={desc}>{desc}</p>
      
      {/* Start Goal UI */}
      <div className="mb-4 flex gap-2">
        <input 
          type="text" 
          placeholder="Set a new goal for this agent..." 
          className="w-full rounded border border-trident-border/50 bg-trident-bg p-2 text-sm text-trident-text focus:border-trident-accent focus:outline-none"
          value={goal}
          onChange={e => setGoal(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleStartGoal()}
          disabled={isStarting}
        />
        <button 
          className="flex items-center gap-1 rounded bg-trident-accent px-4 py-2 text-sm font-bold text-black dark:text-white hover:bg-trident-accent/80 disabled:opacity-50"
          onClick={handleStartGoal}
          disabled={isStarting || !goal.trim()}
        >
          {isStarting ? <Loader2 size={16} className="animate-spin" /> : <PlayCircle size={16} />}
          <span className="ml-1">Start</span>
        </button>
      </div>

      {/* Agent selector: lead + subagents + guardrail for coder56 runs */}
      {isCoder56 && agents.length > 0 && (
        <div className="mb-2 flex items-center gap-1 overflow-x-auto pb-1">
          {agents.map(a => {
            const isActive = a.session_id === selectedAgentId;
            return (
              <button
                key={a.session_id}
                onClick={() => setPinnedAgentId(a.session_id)}
                title={a.title || a.label}
                className={`flex-shrink-0 rounded-full px-2.5 py-1 text-[11px] font-medium border transition-colors ${
                  isActive
                    ? 'bg-trident-accent/20 text-trident-accent border-trident-accent/50'
                    : 'bg-trident-bg text-trident-muted border-trident-border/50 hover:text-trident-text'
                }`}
              >
                {a.label}
              </button>
            );
          })}
          {pinnedAgentId && (
            <button
              onClick={() => setPinnedAgentId(null)}
              title="Follow the most recently active agent automatically"
              className="flex-shrink-0 rounded-full px-2.5 py-1 text-[11px] font-medium border border-dashed border-trident-border/50 text-trident-muted hover:text-trident-text"
            >
              auto-follow latest
            </button>
          )}
        </div>
      )}

      <div className="mb-2 flex gap-1 rounded-lg bg-trident-bg p-1">
        <div className="flex-1 rounded-md px-2 py-1 text-xs font-medium bg-trident-accent/20 text-trident-accent flex items-center justify-center">
          <MessageSquare size={12} className="mr-1" />
          {selectedAgent && selectedAgent.session_id !== activeSession?.session_id
            ? `${selectedAgent.label} — ${messages.length} msgs`
            : `Messages (${messages.length})`}
        </div>
      </div>

      {messages.length === 0 ? (
        <p className="py-4 text-center text-sm text-trident-muted flex-1 flex items-center justify-center border border-dashed border-trident-border/50 rounded-lg">
          {activeSession ? 'Waiting for messages...' : 'No active goal. Set a goal above to start.'}
        </p>
      ) : (
        <div className="flex-1 overflow-auto border border-trident-border/50 rounded-lg bg-trident-bg">
          <SessionStream messages={messages} />
        </div>
      )}
    </div>
  );
}

export function AgentsPage() {
  const { replay } = useReplayContext();
  const [assignments, setAssignments] = useState<AgentStateAssignment[]>([]);
  const [templates, setTemplates] = useState<Record<string, AgentTemplate>>({});
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [runningTopologyIds, setRunningTopologyIds] = useState<Set<string>>(new Set());
  const [topologyDetails, setTopologyDetails] = useState<Record<string, Topology>>({});
  const [verifierApplying, setVerifierApplying] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (replay.replayId) return; // don't poll live management data while a replay is loaded
    let cancelled = false;
    let timer: number | undefined;

    async function loadData() {
      try {
        const [tplsResult, containersResult] = await Promise.allSettled([
          api.getAgentTemplates(),
          api.discoverContainers({ state: ContainerState.RUNNING, includeStopped: false })
        ]);

        if (cancelled) return;

        if (tplsResult.status === 'fulfilled') {
          setTemplates(tplsResult.value.agents);
        } else {
          console.error("Failed to load agent templates", tplsResult.reason);
        }

        if (containersResult.status === 'rejected') {
          console.error("Failed to discover running containers", containersResult.reason);
          return;
        }

        const runningIds = new Set<string>(
          containersResult.value.containers
            .map((c: ContainerInfo) => c.topology_id)
            .filter((id): id is string => Boolean(id))
        );
        setRunningTopologyIds(runningIds);

        // Only request assignments for running topologies. The unfiltered
        // endpoint loads every saved topology and is unnecessarily expensive.
        const assignmentResults = await Promise.allSettled(
          Array.from(runningIds).map(topologyId =>
            api.getAgentAssignments({ topologyId })
          )
        );
        if (cancelled) return;
        const successfulAssignments = assignmentResults.filter(
          (result): result is PromiseFulfilledResult<AgentStateAssignment[]> =>
            result.status === 'fulfilled'
        );
        const assigns = assignmentResults.flatMap(result => {
          if (result.status === 'fulfilled') return result.value;
          console.error("Failed to load assignments for a running topology", result.reason);
          return [];
        });
        // Preserve the last good data if every assignment request failed.
        if (runningIds.size === 0 || successfulAssignments.length > 0) {
          setAssignments(assigns);
        }

        // Fetch full topology details for running topologies so we can read guardrail_enabled per host.
        const details: Record<string, Topology> = {};
        await Promise.all(
          Array.from(runningIds).map(async (tid) => {
            try {
              const topo = await api.getTopology(tid);
              details[tid] = topo;
            } catch (e) {
              console.error(`Failed to load topology ${tid}`, e);
            }
          })
        );
        if (!cancelled) setTopologyDetails(details);
      } catch (err) {
        console.error("Failed to load agent data", err);
      } finally {
        if (!cancelled) {
          setLoading(false);
          timer = window.setTimeout(loadData, 10000);
        }
      }
    }
    loadData();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [replay.replayId]);

  // Fetch the global session list once for the page and share it with all
  // panels. Previously every panel fetched the same list independently.
  useEffect(() => {
    if (replay.replayId) return;
    let cancelled = false;
    let timer: number | undefined;

    const pollSessions = async () => {
      try {
        const nextSessions = await api.listSessions();
        if (!cancelled) setSessions(nextSessions);
      } catch (err) {
        console.error("Failed to load sessions", err);
      } finally {
        if (!cancelled) timer = window.setTimeout(pollSessions, 3000);
      }
    };

    pollSessions();
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [replay.replayId]);

  const activeAssignments = assignments.filter(a => runningTopologyIds.has(a.topology_id));

  // Map topology_id:host_id -> guarded status.
  // guardrail_enabled undefined/null means auto-armed when a guarded agent (coder56/soc_god) is present.
  const hostGuardedMap = useMemo(() => {
    const map: Record<string, boolean> = {};
    const guardedAgents = new Set<string>(['coder56', 'soc_god']);
    Object.values(topologyDetails).forEach((topo) => {
      (topo.networks || []).forEach((net) => {
        (net.hosts || []).forEach((host: Host) => {
          const hasGuarded = (host.agents || []).some((a) => guardedAgents.has(a));
          const guardrailOn = host.guardrail_enabled ?? hasGuarded;
          map[`${topo.id}:${host.id}`] = guardrailOn;
        });
      });
    });
    return map;
  }, [topologyDetails]);

  const hostVerifierMap = useMemo(() => {
    const map: Record<string, boolean> = {};
    Object.values(topologyDetails).forEach((topo) => {
      (topo.networks || []).forEach((net) => {
        (net.hosts || []).forEach((host: Host) => {
          map[`${topo.id}:${host.id}`] = host.coder56_verifier_enabled ?? true;
        });
      });
    });
    return map;
  }, [topologyDetails]);

  const toggleVerifier = async (assignment: AgentStateAssignment) => {
    const key = `${assignment.topology_id}:${assignment.host_id}`;
    const enabled = !(hostVerifierMap[key] ?? true);
    setVerifierApplying(prev => ({ ...prev, [key]: true }));
    try {
      const result = await api.setCoder56Verifier(
        assignment.topology_id,
        assignment.host_id,
        enabled,
        true,
      );
      setTopologyDetails(prev => {
        const current = prev[assignment.topology_id];
        if (!current) return prev;
        return {
          ...prev,
          [assignment.topology_id]: {
            ...current,
            networks: (current.networks || []).map(net => ({
              ...net,
              hosts: (net.hosts || []).map(host => (
                host.id === assignment.host_id
                  ? { ...host, coder56_verifier_enabled: enabled }
                  : host
              )),
            })),
          },
        };
      });

      if (result.job_id) {
        let completed = false;
        for (let attempt = 0; attempt < 200; attempt++) {
          const job = await api.getTopologyJob(assignment.topology_id, result.job_id);
          if (job.status === 'completed') {
            completed = true;
            break;
          }
          if (job.status === 'failed') {
            throw new Error(job.error || 'Topology restart failed');
          }
          await new Promise(resolve => window.setTimeout(resolve, 1500));
        }
        if (!completed) throw new Error('Timed out applying coder56 verifier mode');
      }
    } catch (err) {
      console.error('Failed to update coder56 verifier mode', err);
      window.alert(err instanceof Error ? err.message : 'Failed to update coder56 verifier mode');
    } finally {
      setVerifierApplying(prev => ({ ...prev, [key]: false }));
    }
  };

  // Replay mode: show replayed agent activity synced to playback, instead of the live management UI.
  if (replay.replayId) {
    return (
      <div className="flex h-full flex-col gap-6 overflow-auto">
        <ReplayHeader title="Agents" subtitle="Agent execution" />
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 pb-6">
          <ReplayAgentView
            agentKey="coder56"
            label="coder56"
            desc="Red-team attacker — recon, exploitation, persistence"
            color="text-red-700 dark:text-red-400"
          />
          <ReplayAgentView
            agentKey="db_admin"
            label="db_admin"
            desc='Benign DBA persona "John Scott" — routine DB tasks'
            color="text-green-700 dark:text-green-400"
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-6 overflow-auto">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-heading text-2xl font-bold text-trident-text">Agents</h2>
          <p className="text-sm text-trident-muted">
            Manage deployed agents, set goals, and view their execution logs
          </p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12 text-trident-muted">
          <Loader2 className="animate-spin mr-2" /> Loading agents...
        </div>
      ) : activeAssignments.length === 0 ? (
        <div className="card text-center py-12">
          <p className="text-trident-muted">No agents are currently deployed.</p>
          <p className="text-xs text-trident-muted mt-2">Go to the Topology page to assign agents to hosts.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 pb-6">
          {activeAssignments.map((a) => (
            <AgentPanel
              key={a.id}
              assignment={a}
              template={templates[a.agent_type]}
              sessions={sessions}
              isGuarded={hostGuardedMap[`${a.topology_id}:${a.host_id}`] ?? false}
              verifierEnabled={hostVerifierMap[`${a.topology_id}:${a.host_id}`] ?? true}
              verifierApplying={verifierApplying[`${a.topology_id}:${a.host_id}`] ?? false}
              onToggleVerifier={() => toggleVerifier(a)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
