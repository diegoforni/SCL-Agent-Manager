import { useState, useEffect, useCallback, useRef } from 'react';
import { createPortal } from 'react-dom';
import {
  ChevronDown, ChevronRight, Server, Network as NetworkIcon,
  Plus, X, Save, Play, Square, CheckCircle, AlertCircle, Loader2, Sparkles
} from 'lucide-react';
import api, { type PresetSummary, type BenignTopology, type BenignPersonality } from '@/api';
import type { Topology, Network, Host, AgentTemplate } from '@/types';
import { BenignConfigPanel } from '@/components/BenignConfigPanel';

// ─── Agent catalogue ────────────────────────────────────────────────────────
// Presentation only (label + colour). The *set* of available agents is fetched
// from the backend (GET /api/agents/templates) so the dropdown always reflects
// what actually exists, instead of a hardcoded list that drifts out of sync.
type TemplateMap = Record<string, AgentTemplate>;

const AGENT_STYLE: Record<string, { label?: string; color: string; bg: string }> = {
  coder56:  { label: 'Coder 5.6', color: 'text-violet-700 dark:text-violet-300', bg: 'bg-violet-100 dark:bg-violet-900/40' },
  db_admin: { label: 'Benign Agent', color: 'text-green-700 dark:text-green-300', bg: 'bg-green-100 dark:bg-green-900/40' },
  soc_god:  { label: 'SOC God',   color: 'text-red-700 dark:text-red-300',    bg: 'bg-red-100 dark:bg-red-900/40'    },
};

function metaFor(type: string, templates: TemplateMap) {
  const style = AGENT_STYLE[type];
  return {
    label: style?.label ?? templates[type]?.name ?? type,
    color: style?.color ?? 'text-gray-700 dark:text-gray-300',
    bg: style?.bg ?? 'bg-gray-100 dark:bg-gray-700',
  };
}

// ─── Start-error friendly messages ──────────────────────────────────────────
// docker-compose failures arrive verbatim as stderr; add a one-line hint for the
// cases we can diagnose so the user knows what to do, not just what broke.
function friendlyStartError(message?: string): string {
  const msg = (message ?? 'Unknown error').trim();
  if (/Pool overlaps with other one/i.test(msg)) {
    return `${msg}  (subnet collision — another running topology already uses the same 10.77.x.x CIDR; stop it first)`;
  }
  if (/no such image|manifest unknown/i.test(msg)) {
    return `${msg}  (an image is missing — rebuild the topology/SCL base images)`;
  }
  return msg;
}

// ─── List summary type (what /api/topologies returns) ───────────────────────
interface TopologySummary {
  id: string;
  name: string;
  version: string;
  network_count: number;
  host_count: number;
  is_running: boolean;
}

// ─── Agent chip ─────────────────────────────────────────────────────────────
function AgentChip({ agent, templates, onRemove }: { agent: string; templates: TemplateMap; onRemove?: () => void }) {
  const meta = metaFor(agent, templates);
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold ${meta.bg} ${meta.color}`}>
      {meta.label}
      {onRemove && (
        <button onClick={onRemove} className="hover:opacity-60 transition-opacity" title={`Remove ${meta.label}`}>
          <X size={11} />
        </button>
      )}
    </span>
  );
}

// ─── Add-agent dropdown ──────────────────────────────────────────────────────
// Rendered through a portal (document.body) with position: fixed so it escapes
// the overflow-hidden network card and the overflow-auto scroll containers that
// otherwise clip an absolutely-positioned menu (the old "only first agent
// visible / can't scroll" bug).
function AddAgentButton({ currentAgents, agentTypes, templates, onAdd }: {
  currentAgents: string[];
  agentTypes: string[];
  templates: TemplateMap;
  onAdd: (a: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const available = agentTypes.filter(a => !currentAgents.includes(a));

  const toggle = () => {
    if (open) { setOpen(false); return; }
    if (available.length === 0) return;
    const r = btnRef.current?.getBoundingClientRect();
    if (!r) return;
    const menuH = Math.min(available.length * 30 + 8, 240);
    let top = r.bottom + 4;
    if (top + menuH > window.innerHeight - 8) top = Math.max(8, r.top - menuH - 4); // flip up if needed
    const left = Math.min(r.left, window.innerWidth - 184);
    setPos({ top, left });
    setOpen(true);
  };

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node;
      if (menuRef.current?.contains(t) || btnRef.current?.contains(t)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    const close = () => setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
    };
  }, [open]);

  if (available.length === 0) return null;

  return (
    <div className="relative">
      <button
        ref={btnRef}
        onClick={toggle}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold
                     border border-dashed border-gray-400 dark:border-gray-500 text-gray-500 dark:text-gray-400 hover:border-blue-500 dark:hover:border-blue-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors"
      >
        <Plus size={11} /> Add agent
      </button>
      {open && pos && createPortal(
        <div
          ref={menuRef}
          style={{ position: 'fixed', top: pos.top, left: pos.left }}
          className="z-50 max-h-60 w-44 overflow-y-auto bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 py-1"
        >
          {available.map(a => {
            const m = metaFor(a, templates);
            return (
              <button
                key={a}
                onClick={() => { onAdd(a); setOpen(false); }}
                className={`w-full text-left px-3 py-1.5 text-xs font-semibold hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors ${m.color}`}
              >
                {m.label}
              </button>
            );
          })}
        </div>,
        document.body
      )}
    </div>
  );
}

// ─── Host row ────────────────────────────────────────────────────────────────
function HostRow({
  host, topologyId, networkId, agentTypes, templates, guardrailOn, verifierOn, onToggleGuardrail,
  onToggleVerifier, onAgentAdd, onAgentRemove, benign,
}: {
  host: Host;
  topologyId: string | null;
  networkId: string;
  agentTypes: string[];
  templates: TemplateMap;
  guardrailOn: boolean;
  verifierOn: boolean;
  onToggleGuardrail: () => void;
  onToggleVerifier: () => void;
  onAgentAdd: (agentType: string) => void;
  onAgentRemove: (agentType: string) => void;
  benign: {
    topo: BenignTopology | null;
    personalities: BenignPersonality[];
    onChange: (cfg: { system_prompt: string; goal: string } | null) => void;
    onApplied: (topologyId: string | null) => void;
  };
}) {
  const agents = host.agents ?? [];
  const hasCoder56 = agents.includes('coder56');
  return (
    <div className="space-y-1">
    <div className="flex flex-wrap items-center gap-2 p-2 bg-gray-50 dark:bg-gray-800/60 rounded-lg">
      <Server size={14} className="text-green-500 dark:text-green-400 flex-shrink-0" />
      <span className="text-sm font-medium min-w-[100px] max-w-[180px] truncate" title={host.name}>{host.name}</span>
      <span className="text-xs px-2 py-0.5 bg-gray-200 dark:bg-gray-700 rounded-full text-gray-600 dark:text-gray-300">
        {host.type}
      </span>
      {/* Guardrail/gate toggle. Auto-on when a guarded agent (coder56/
          soc_god) is present; persists via saveTopology round-trip. */}
      <label
        title="Guardrail/gate: audit this host's bash via a second opencode agent (auto-on for coder56/soc_god)"
        className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full cursor-pointer select-none ${
          guardrailOn
            ? 'bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300'
            : 'bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400'
        }`}
      >
        <input type="checkbox" checked={guardrailOn} onChange={onToggleGuardrail} className="accent-amber-500" />
        🛡 guardrail
      </label>
      {hasCoder56 && (
        <label
          title="Independent coder56 finding verifier. Turn off for legacy single-agent execution."
          className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full cursor-pointer select-none ${
            verifierOn
              ? 'bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-300'
              : 'bg-gray-200 dark:bg-gray-700 text-gray-500 dark:text-gray-400'
          }`}
        >
          <input type="checkbox" checked={verifierOn} onChange={onToggleVerifier} className="accent-violet-500" />
          ✓ verifier
        </label>
      )}
      <div className="flex flex-wrap items-center gap-1.5 ml-auto">
        {agents.map(a => (
          <AgentChip key={a} agent={a} templates={templates} onRemove={() => onAgentRemove(a)} />
        ))}
        <AddAgentButton currentAgents={agents} agentTypes={agentTypes} templates={templates} onAdd={onAgentAdd} />
      </div>
      {benign && (host.agents ?? []).includes('db_admin') && (
        <BenignConfigPanel
          topologyId={topologyId}
          networkId={networkId}
          host={host}
          benignTopo={benign.topo}
          personalities={benign.personalities}
          onChange={(cfg) => benign.onChange(cfg)}
          onApplied={benign.onApplied}
        />
      )}
      </div>
    </div>
  );
}

// ─── Main page ───────────────────────────────────────────────────────────────
export function TopologyPage() {
  const [summaries, setSummaries] = useState<TopologySummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // working copy — editable in-place
  const [topology, setTopology] = useState<Topology | null>(null);
  const [expandedNetworks, setExpandedNetworks] = useState<Set<string>>(new Set());

  const [listLoading, setListLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);
  // Available agents — authoritative list from /api/agents/templates (falls back
  // to the AGENT_STYLE keys below until the fetch resolves or if it fails).
  const [agentTypes, setAgentTypes] = useState<string[]>(Object.keys(AGENT_STYLE));
  const [templates, setTemplates] = useState<TemplateMap>({});
  // Benign agent wizard data: annotated topology (can-carry-agent, grants) and
  // the personality catalogue, both served by /api/benign/*.
  const [benignTopo, setBenignTopo] = useState<BenignTopology | null>(null);
  const [personalities, setPersonalities] = useState<BenignPersonality[]>([]);
  // Last start-failure message for the selected topology (shown as a banner until
  // dismissed / a new start / a topology switch). Empty when the last start worked.
  const [startError, setStartError] = useState<string | null>(null);
  // Bumped on each Start attempt and topology switch so an in-flight job poll can
  // detect it's stale and bail out (no setState after unmount / on a different topo).
  const pollToken = useRef(0);

  const showToast = (msg: string, ok = true) => {
    setToast({ msg, ok });
    setTimeout(() => setToast(null), 3500);
  };

  // Load list
  const loadList = useCallback(() => {
    setListLoading(true);
    api.getTopologies()
      .then((data: any) => { setSummaries(data.topologies ?? []); setListLoading(false); })
      .catch(() => setListLoading(false));
  }, []);

  useEffect(() => { loadList(); }, [loadList]);

  // Starter presets — the plugin's presets/ catalogue (what a fresh clone ships).
  // Loaded once, best-effort: the topology list works without them.
  const [presets, setPresets] = useState<PresetSummary[]>([]);
  const [instantiating, setInstantiating] = useState<string | null>(null);

  useEffect(() => {
    api.getPresets()
      .then((data) => setPresets(data.presets ?? []))
      .catch(() => setPresets([]));
  }, []);

  // Load the authoritative list of available agents from the backend.
  const loadAgentTemplates = useCallback(() => {
    api.getAgentTemplates()
      .then((data) => {
        const t = ((data as any).agents ?? {}) as TemplateMap;
        setTemplates(t);
        const keys = Object.keys(t);
        if (keys.length) setAgentTypes(keys);
      })
      .catch(() => { /* keep AGENT_STYLE defaults */ });
  }, []);
  useEffect(() => { loadAgentTemplates(); }, [loadAgentTemplates]);

  // Load detail
  const selectTopology = async (id: string) => {
    setSelectedId(id);
    setDirty(false);
    setDetailLoading(true);
    setExpandedNetworks(new Set());
    // Switching topology invalidates any in-flight start poll and its banner.
    pollToken.current += 1;
    setStartError(null);
    try {
      const detail = await api.getTopology(id);
      setTopology(detail);
      setBenignTopo(null);
      // Auto-expand all networks
      setExpandedNetworks(new Set((detail.networks ?? []).map((n: Network) => n.id)));
      // Best-effort: benign wizard data (fails soft — page works without it)
      api.getBenignTopology(id).then(setBenignTopo).catch(() => setBenignTopo(null));
      api.getBenignPersonalities().then((r) => setPersonalities(r.personalities)).catch(() => {});
    } catch {
      showToast('Failed to load topology detail', false);
    } finally {
      setDetailLoading(false);
    }
  };

  const reloadBenignTopo = useCallback((tid: string | null) => {
    if (!tid) return;
    api.getBenignTopology(tid).then(setBenignTopo).catch(() => {});
  }, []);

  const toggleNetwork = (networkId: string) => {
    setExpandedNetworks(prev => {
      const next = new Set(prev);
      next.has(networkId) ? next.delete(networkId) : next.add(networkId);
      return next;
    });
  };

  // ── Mutate agents ──────────────────────────────────────────────────────────
  const mutateHost = (networkId: string, hostId: string, mutateFn: (h: Host) => Host) => {
    setTopology(prev => {
      if (!prev) return prev;
      return {
        ...prev,
        networks: (prev.networks ?? []).map(n =>
          n.id !== networkId ? n : {
            ...n,
            hosts: (n.hosts ?? []).map(h => h.id !== hostId ? h : mutateFn(h))
          }
        )
      };
    });
    setDirty(true);
  };

  const addAgent = (networkId: string, hostId: string, agentType: string) => {
    mutateHost(networkId, hostId, h => ({
      ...h,
      agents: [...(h.agents ?? []).filter(a => a !== agentType), agentType]
    }));
  };

  const removeAgent = (networkId: string, hostId: string, agentType: string) => {
    mutateHost(networkId, hostId, h => ({
      ...h,
      agents: (h.agents ?? []).filter(a => a !== agentType),
      // drop the benign prompt override together with its agent chip
      agent_config: agentType === 'db_admin'
        ? Object.fromEntries(Object.entries(h.agent_config ?? {}).filter(([k]) => k !== 'db_admin'))
        : h.agent_config,
    }));
  };

  // Called by the benign panel whenever the personality/targets pickers regenerate
  // the prompt (null clears the override, e.g. selections not complete yet).
  const updateBenignConfig = (networkId: string, hostId: string,
                              cfg: { system_prompt: string; goal: string } | null) => {
    mutateHost(networkId, hostId, h => {
      const rest = Object.fromEntries(Object.entries(h.agent_config ?? {}).filter(([k]) => k !== 'db_admin'));
      return { ...h, agent_config: cfg ? { ...rest, db_admin: cfg } : rest };
    });
  };

  // Guardrail/gate membership — MUST mirror the plugin's GUARDED_AGENTS (app.py)
  // so the checkbox auto-default matches what compose-generation produces.
  const hasGuardedAgent = (h: Host) =>
    !!(h.agents ?? []).some(a => a === 'coder56' || a === 'soc_god');

  const toggleGuardrail = (networkId: string, hostId: string) => {
    mutateHost(networkId, hostId, h => ({
      ...h,
      guardrail_enabled: !(h.guardrail_enabled ?? hasGuardedAgent(h)),
    }));
  };

  const toggleVerifier = (networkId: string, hostId: string) => {
    mutateHost(networkId, hostId, h => ({
      ...h,
      coder56_verifier_enabled: !(h.coder56_verifier_enabled ?? true),
    }));
  };

  // ── Create a brand-new topology (plugin mints a fresh id) ──────────────────
  const createTopology = async () => {
    const name = window.prompt('New topology name', `lab-${new Date().toISOString().slice(0, 10)}`);
    if (!name) return;
    try {
      const created = await api.createTopology({
        name,
        networks: [{ id: 'lan', name: 'lan', hosts: [{ id: 'host1', name: 'host1' }] } as unknown as Network],
      });
      await loadList();
      await selectTopology(created.id);
      showToast(`Created topology “${created.name}”`);
    } catch (e) {
      showToast('Failed to create topology', false);
    }
  };

  // ── Instantiate a starter preset ──────────────────────────────────────────
  // One click → editable draft copy of the preset; the plugin mints a fresh
  // id so repeated instantiations never collide.
  const doInstantiatePreset = async (preset: PresetSummary) => {
    if (instantiating) return;
    setInstantiating(preset.preset_id);
    try {
      const created = await api.instantiatePreset(preset.preset_id);
      await loadList();
      await selectTopology(created.id);
      showToast(`Instantiated “${created.name}”`);
    } catch (e: any) {
      showToast(e?.message ?? 'Failed to instantiate preset', false);
    } finally {
      setInstantiating(null);
    }
  };

  // ── Save ───────────────────────────────────────────────────────────────────
  const save = async () => {
    if (!topology || !selectedId) return;
    setSaving(true);
    try {
      const saved = await api.saveTopology(selectedId, topology.networks ?? []);
      setTopology(saved);
      setDirty(false);
      // Refresh list to update updated_at timestamp
      loadList();
      showToast('Agents saved ✓');
    } catch (e: any) {
      showToast(e?.message ?? 'Save failed', false);
    } finally {
      setSaving(false);
    }
  };

  // ── Start / Stop ───────────────────────────────────────────────────────────
  const startTopology = async () => {
    if (!selectedId) return;
    // Auto-save first if dirty
    if (dirty) await save();
    // Invalidate any prior poll and clear the previous failure banner.
    const token = (pollToken.current += 1);
    const id = selectedId;
    setStartError(null);
    setStarting(true);
    try {
      const r = await api.startTopology(id);
      // No job_id (older plugin) → keep the old optimistic behaviour.
      if (!r.job_id) {
        showToast(r.message ?? 'Topology started');
        loadList();
        return;
      }
      // Poll the async start job so we can report real failures (e.g. a
      // docker-compose subnet collision) instead of a silent "stopped".
      const POLL_MS = 1500;
      const MAX_ATTEMPTS = 200; // ~5 min, to cover first-run image builds
      for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        if (pollToken.current !== token) return; // superseded by another start/switch
        const job = await api.getTopologyJob(id, r.job_id);
        if (pollToken.current !== token) return;
        if (job.status === 'completed') {
          showToast('Topology started ✓');
          loadList();
          return;
        }
        if (job.status === 'failed') {
          const msg = friendlyStartError(job.error);
          setStartError(msg);
          showToast(`Start failed: ${msg}`, false);
          loadList();
          return;
        }
        await new Promise(resolve => setTimeout(resolve, POLL_MS));
      }
      // Timed out while still building/starting — don't claim failure.
      showToast('Still starting — first run may build images; check the list shortly.');
      loadList();
    } catch (e: any) {
      showToast(e?.message ?? 'Start failed', false);
    } finally {
      if (pollToken.current === token) setStarting(false);
    }
  };

  const stopTopology = async () => {
    if (!selectedId) return;
    setStopping(true);
    try {
      const r = await api.stopTopology(selectedId);
      showToast(r.message ?? 'Topology stopped');
      loadList();
    } catch (e: any) {
      showToast(e?.message ?? 'Stop failed', false);
    } finally {
      setStopping(false);
    }
  };

  const selectedSummary = summaries.find(s => s.id === selectedId);
  const isRunning = selectedSummary?.is_running ?? false;

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex h-full flex-col gap-4 overflow-hidden p-6">

      {/* Header */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Network Topologies</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">Select a topology, assign agents to hosts, then start.</p>
        </div>
      </div>

      {/* Toast */}
      {toast && (
        <div className={`fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-lg text-sm font-medium
          ${toast.ok ? 'bg-green-50 dark:bg-green-900/30 text-green-800 dark:text-green-200 border border-green-200 dark:border-green-700' : 'bg-red-50 dark:bg-red-900/30 text-red-800 dark:text-red-200 border border-red-200 dark:border-red-700'}`}
        >
          {toast.ok ? <CheckCircle size={16} /> : <AlertCircle size={16} />}
          {toast.msg}
        </div>
      )}

      <div className="grid grid-cols-3 gap-5 flex-1 min-h-0">

        {/* ── Left: topology list ── */}
        <div className="flex flex-col gap-2 overflow-auto">
          <div className="flex items-center gap-2 flex-shrink-0">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Topologies</h2>
            <button
              onClick={createTopology}
              title="Create a new topology"
              className="flex items-center gap-1 text-xs px-2 py-1 rounded-lg bg-blue-500 hover:bg-blue-600 text-white font-medium transition-colors"
            >
              <Plus size={12} /> New
            </button>
          </div>
          {listLoading ? (
            <p className="text-sm text-gray-400 dark:text-gray-500">Loading…</p>
          ) : summaries.map(s => (
            <button
              key={s.id}
              onClick={() => selectTopology(s.id)}
              className={`w-full p-3.5 rounded-xl border-2 text-left transition-all ${
                selectedId === s.id
                  ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                  : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-500'
              }`}
            >
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-sm truncate" title={s.name}>{s.name}</h3>
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${s.is_running ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'}`} />
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                {s.network_count} network{s.network_count !== 1 ? 's' : ''} · {s.host_count} host{s.host_count !== 1 ? 's' : ''}
              </p>
              <p className="text-xs font-medium mt-1 text-gray-400 dark:text-gray-500">{s.is_running ? '● running' : '○ stopped'}</p>
            </button>
          ))}

          {/* ── Starter presets (plugin presets/ catalogue) ── */}
          {presets.length > 0 && (
            <>
              <div className="flex items-center gap-1.5 flex-shrink-0 pt-3 mt-1 border-t border-gray-200 dark:border-gray-700">
                <Sparkles size={13} className="text-amber-500" />
                <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">Starter presets</h2>
              </div>
              {presets.map(p => (
                <div
                  key={p.preset_id}
                  className="p-3.5 rounded-xl border-2 border-dashed border-gray-200 dark:border-gray-700"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="font-semibold text-sm truncate" title={p.preset_name}>{p.preset_name}</h3>
                    <button
                      onClick={() => doInstantiatePreset(p)}
                      disabled={instantiating !== null}
                      title={`Create a new editable topology from the ${p.preset_name} preset`}
                      className="flex items-center gap-1 text-xs px-2 py-1 rounded-lg bg-amber-500 hover:bg-amber-600 disabled:opacity-50 text-white font-medium transition-colors flex-shrink-0"
                    >
                      {instantiating === p.preset_id
                        ? <Loader2 size={12} className="animate-spin" />
                        : <Plus size={12} />}
                      {instantiating === p.preset_id ? 'Creating…' : 'Instantiate'}
                    </button>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                    {p.network_count} network{p.network_count !== 1 ? 's' : ''} · {p.host_count} host{p.host_count !== 1 ? 's' : ''}
                  </p>
                  {p.description && (
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 line-clamp-3" title={p.description}>{p.description}</p>
                  )}
                  {p.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {p.tags.map(t => (
                        <span key={t} className="px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 text-[10px] font-medium">{t}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </>
          )}
        </div>

        {/* ── Right: detail + editor ── */}
        <div className="col-span-2 flex flex-col gap-3 overflow-auto">
          {!selectedId ? (
            <div className="flex items-center justify-center h-full text-gray-400 dark:text-gray-500">
              Select a topology to edit agents
            </div>
          ) : detailLoading ? (
            <div className="flex items-center justify-center h-full gap-2 text-gray-400 dark:text-gray-500">
              <Loader2 size={18} className="animate-spin" /> Loading…
            </div>
          ) : topology ? (
            <>
              {/* Start-failure banner (from the most recent start attempt) */}
              {startError && (
                <div className="flex items-start gap-2 flex-shrink-0 bg-red-50 dark:bg-red-900/30 text-red-800 dark:text-red-200 border border-red-200 dark:border-red-700 rounded-xl px-4 py-3 text-sm">
                  <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <p className="font-semibold">Topology failed to start</p>
                    <p className="break-words whitespace-pre-wrap">{startError}</p>
                  </div>
                  <button
                    onClick={() => setStartError(null)}
                    title="Dismiss"
                    className="ml-auto flex-shrink-0 hover:opacity-60 transition-opacity"
                  >
                    <X size={16} />
                  </button>
                </div>
              )}
              {/* Action bar */}
              <div className="flex items-center justify-between flex-shrink-0 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl px-4 py-3">
                <div>
                  <h2 className="font-bold text-base truncate" title={topology.name}>{topology.name}</h2>
                  <p className="text-xs text-gray-500 dark:text-gray-400">v{topology.version}
                    {dirty && <span className="ml-2 text-amber-600 dark:text-amber-400 font-semibold">● unsaved changes</span>}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {dirty && (
                    <button
                      onClick={save}
                      disabled={saving}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                                 text-white text-sm font-semibold rounded-lg transition-colors"
                    >
                      {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                      {saving ? 'Saving…' : 'Save agents'}
                    </button>
                  )}
                  {isRunning ? (
                    <button
                      onClick={stopTopology}
                      disabled={stopping}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-red-600 hover:bg-red-700 disabled:opacity-50
                                 text-white text-sm font-semibold rounded-lg transition-colors"
                    >
                      {stopping ? <Loader2 size={14} className="animate-spin" /> : <Square size={14} />}
                      {stopping ? 'Stopping…' : 'Stop'}
                    </button>
                  ) : (
                    <button
                      onClick={startTopology}
                      disabled={starting}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-700 disabled:opacity-50
                                 text-white text-sm font-semibold rounded-lg transition-colors"
                    >
                      {starting ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
                      {starting ? 'Starting…' : 'Start'}
                    </button>
                  )}
                </div>
              </div>

              {/* Networks + hosts */}
              <div className="space-y-2 overflow-auto">
                {(topology.networks ?? []).map((network: Network) => (
                  <div key={network.id} className="border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden">
                    {/* Network header */}
                    <button
                      onClick={() => toggleNetwork(network.id)}
                      className="w-full flex items-center gap-2 px-4 py-2.5 bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700/80 transition-colors"
                    >
                      {expandedNetworks.has(network.id) ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                      <NetworkIcon size={15} className="text-blue-500" />
                      <span className="font-semibold text-sm truncate" title={network.name}>{network.name}</span>
                      <span className="text-xs text-gray-400 dark:text-gray-500">{network.cidr}</span>
                      {network.internet && (
                        <span className="ml-1 text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300 rounded-full">internet</span>
                      )}
                      <span className="ml-auto text-xs text-gray-400 dark:text-gray-500">
                        {(network.hosts ?? []).length} host{(network.hosts ?? []).length !== 1 ? 's' : ''}
                      </span>
                    </button>

                    {/* Hosts */}
                    {expandedNetworks.has(network.id) && (
                      <div className="px-4 py-3 space-y-2">
                        {(network.hosts ?? []).length === 0 ? (
                          <p className="text-xs text-gray-400 dark:text-gray-500">No hosts</p>
                        ) : (network.hosts ?? []).map((host: Host) => (
                          <HostRow
                            key={host.id}
                            host={host}
                            topologyId={selectedId}
                            networkId={network.id}
                            agentTypes={agentTypes}
                            templates={templates}
                            guardrailOn={host.guardrail_enabled ?? hasGuardedAgent(host)}
                            verifierOn={host.coder56_verifier_enabled ?? true}
                            onToggleGuardrail={() => toggleGuardrail(network.id, host.id)}
                            onToggleVerifier={() => toggleVerifier(network.id, host.id)}
                            onAgentAdd={a => addAgent(network.id, host.id, a)}
                            onAgentRemove={a => removeAgent(network.id, host.id, a)}
                            benign={{
                              topo: benignTopo,
                              personalities,
                              onChange: cfg => updateBenignConfig(network.id, host.id, cfg),
                              onApplied: tid => reloadBenignTopo(tid),
                            }}
                          />
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {/* Legend */}
              <div className="flex-shrink-0 flex flex-wrap gap-2 pt-1">
                <p className="text-xs text-gray-400 dark:text-gray-500 w-full">Available agents:</p>
                {agentTypes.map(k => {
                  const m = metaFor(k, templates);
                  return (
                    <span key={k} className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${m.bg} ${m.color}`}>
                      {m.label}
                    </span>
                  );
                })}
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}
