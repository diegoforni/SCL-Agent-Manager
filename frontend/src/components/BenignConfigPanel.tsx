import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, Loader2, Rocket } from 'lucide-react';
import api, { type BenignPersonality, type BenignTopology, type BenignPreview } from '@/api';
import type { Host } from '@/types';

// ─── Benign agent configuration panel ────────────────────────────────────────
// Rendered inline under a host row once the "Benign Agent" type is added to it
// (same flow as adding coder56). Two pickers — personality and the host(s) it
// connects to — regenerate the full system prompt via /api/benign/preview and
// write it into host.agent_config.db_admin, which the page's normal Save
// persists (the topology detail API round-trips agent_config).
//
// Remote placement (dedicated-image hosts, or a cross-network roster) additionally
// needs an operator host and firewall rules; "Apply placement" persists those via
// /api/benign/apply, because they live outside the networks array that Save sends.

interface Props {
  topologyId: string | null;
  networkId: string;
  host: Host;
  benignTopo: BenignTopology | null;
  personalities: BenignPersonality[];
  onChange: (cfg: { system_prompt: string; goal: string } | null) => void;
  onApplied?: (topologyId: string | null) => void;
}

export function BenignConfigPanel({ topologyId, networkId, host, benignTopo, personalities, onChange, onApplied }: Props) {
  const [personalityId, setPersonalityId] = useState('');
  const [mode, setMode] = useState<'resident' | 'remote' | null>(null);
  const [operator, setOperator] = useState('new');
  const [targets, setTargets] = useState<Set<string>>(new Set());
  const [allowInternet, setAllowInternet] = useState(false);
  const [preview, setPreview] = useState<BenignPreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reveal, setReveal] = useState(false);
  const [restart, setRestart] = useState(false);
  const [applying, setApplying] = useState(false);
  const [applyLog, setApplyLog] = useState<string[]>([]);
  const timer = useRef<number | null>(null);

  const allHosts = (benignTopo?.networks ?? []).flatMap((n) => n.hosts.map((h) => ({ ...h, network_id: n.id })));
  const hostInfo = allHosts.find((h) => h.id === host.id) ?? null;
  const genericPeers = allHosts.filter((x) => x.can_carry_agent && x.id !== host.id);
  const effectiveMode: 'resident' | 'remote' | null =
    mode ?? (hostInfo && !hostInfo.can_carry_agent ? 'remote' : hostInfo ? 'resident' : null);
  const currentNetId = benignTopo?.networks.find((n) => n.hosts.some((h) => h.id === host.id))?.id ?? networkId;

  // regenerate the prompt whenever a picker changes (debounced)
  useEffect(() => {
    if (timer.current) window.clearTimeout(timer.current);
    if (!personalityId || !effectiveMode || !topologyId) {
      setPreview(null);
      return;
    }
    if (effectiveMode === 'remote' && targets.size === 0) {
      setPreview(null);
      onChange(null);
      return;
    }
    setPreviewing(true);
    setError(null);
    timer.current = window.setTimeout(() => {
      api.previewBenignAgent({
        topology_id: topologyId,
        personality_id: personalityId,
        mode: effectiveMode,
        host_id: host.id,
        operator: effectiveMode === 'remote' ? operator : undefined,
        targets: effectiveMode === 'remote' ? [...targets] : [],
        allow_internet: allowInternet,
      })
        .then((p) => {
          setPreview(p);
          onChange({ system_prompt: p.system_prompt, goal: p.goal });
        })
        .catch((e) => setError(e?.response?.data?.detail ?? String(e)))
        .finally(() => setPreviewing(false));
    }, 350);
    return () => { if (timer.current) window.clearTimeout(timer.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [personalityId, effectiveMode, operator, targets, allowInternet, topologyId, host.id]);

  const doApplyPlacement = async () => {
    if (!preview) return;
    setApplying(true);
    setApplyLog([]);
    try {
      const res = await api.applyBenignAgent(preview.topology_id, preview.topology_patch, restart);
      setApplyLog(res.changes);
      onApplied?.(preview.topology_id);
    } catch (e) {
      const detail = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setApplyLog([`✘ ${detail ?? String(e)}`]);
    } finally {
      setApplying(false);
    }
  };

  const needsPlacementApply = !!preview && effectiveMode === 'remote'
    && (!!preview.topology_patch.home.new_host || preview.topology_patch.firewall_rules.length > 0);

  return (
    <div className="mx-2 mb-2 rounded-lg border border-green-300 dark:border-green-800 bg-green-50/50 dark:bg-green-900/10 p-2 space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        {/* Picker 1: personality */}
        <label className="flex items-center gap-2 text-xs">
          <span className="font-semibold text-trident-muted">Personality</span>
          <select
            className="text-xs bg-trident-bg border border-trident-border rounded px-2 py-1 text-trident-text"
            value={personalityId}
            onChange={(e) => setPersonalityId(e.target.value)}
          >
            <option value="">— select —</option>
            {personalities.map((p) => (
              <option key={p.id} value={p.id}>{p.name} — {p.role_title}</option>
            ))}
          </select>
        </label>

        {/* Picker 2a: placement (remote only) */}
        {effectiveMode === 'remote' && (
          <label className="flex items-center gap-2 text-xs">
            <span className="font-semibold text-trident-muted">Runs on</span>
            <select
              className="text-xs bg-trident-bg border border-trident-border rounded px-2 py-1 text-trident-text"
              value={operator}
              onChange={(e) => setOperator(e.target.value)}
            >
              <option value="new">➕ new ops-workstation ({currentNetId})</option>
              {genericPeers.map((g) => (
                <option key={g.id} value={`existing:${g.id}`}>{g.id} ({g.network_id})</option>
              ))}
            </select>
          </label>
        )}

        {/* Picker 2b (resident): runs here */}
        {effectiveMode === 'resident' && (
          <span className="text-xs text-trident-muted">Runs on <b>{host.id}</b> — grants target its own services.</span>
        )}
      </div>

      {/* Picker 2 (remote): hosts it can connect to */}
      {effectiveMode === 'remote' && (
        <div>
          <div className="text-xs font-semibold text-trident-muted mb-1">Connects to</div>
          <div className="flex flex-wrap gap-x-3 gap-y-1">
            {allHosts.filter((x) => x.id !== host.id).map((x) => {
              const badge = x.network_id === currentNetId
                ? <span className="text-[9px] text-trident-muted">same subnet</span>
                : <span className="text-[9px] text-amber-600 dark:text-amber-400">+ rule</span>;
              return (
                <label key={x.id} className="flex items-center gap-1 text-xs" title={x.excluded_reason ?? undefined}>
                  <input
                    type="checkbox"
                    disabled={!!x.excluded_reason}
                    checked={targets.has(x.id)}
                    onChange={(e) => {
                      const next = new Set(targets);
                      if (e.target.checked) next.add(x.id); else next.delete(x.id);
                      setTargets(next);
                    }}
                  />
                  <span className="truncate">{x.id}</span>
                  {badge}
                </label>
              );
            })}
            <label className="flex items-center gap-1 text-xs text-trident-muted">
              <input type="checkbox" checked={allowInternet} onChange={(e) => setAllowInternet(e.target.checked)} />
              internet egress
            </label>
          </div>
        </div>
      )}

      {/* status */}
      {previewing && <div className="flex items-center gap-1.5 text-xs text-trident-muted"><Loader2 size={11} className="animate-spin" /> adapting system prompt…</div>}
      {error && <div className="flex items-center gap-1.5 text-xs text-red-600 dark:text-red-400"><AlertTriangle size={11} /> {error}</div>}
      {!previewing && !error && preview && (
        <div className="text-xs text-trident-muted">
          Prompt adapted: <b>{preview.system_prompt.length}</b> chars
          {preview.roster.length > 0 && <> · roster: {preview.roster.join(', ')}</>}
          {' '}· saved into agent_config on this host (persist with <b>Save agents</b>
          {needsPlacementApply ? ' after applying the placement below' : ''})
        </div>
      )}

      {/* remote placement persistence */}
      {needsPlacementApply && (
        <div className="rounded border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 p-2 space-y-1.5">
          <div className="text-xs text-amber-700 dark:text-amber-300">
            The roster needs an operator host and/or firewall rules — these live outside the
            networks payload, so apply them here:
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={doApplyPlacement}
              disabled={applying || !topologyId}
              className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded bg-green-600 text-white hover:bg-green-500 disabled:opacity-50"
            >
              {applying ? <Loader2 size={11} className="animate-spin" /> : <Rocket size={11} />}
              Apply placement
            </button>
            <label className="flex items-center gap-1 text-xs text-trident-muted">
              <input type="checkbox" checked={restart} onChange={(e) => setRestart(e.target.checked)} />
              restart topology
            </label>
          </div>
          {applyLog.map((c, i) => (
            <div key={i} className={`text-[11px] font-mono ${c.startsWith('✘') ? 'text-red-500' : 'text-green-600 dark:text-green-400'}`}>
              {c.startsWith('✘') ? c : `✔ ${c}`}
            </div>
          ))}
        </div>
      )}

      <details className="text-xs">
        <summary className="cursor-pointer text-trident-muted">
          {preview ? `Generated prompt (${preview.system_prompt.length} chars)` : 'Generated prompt'}
        </summary>
        {preview && (
          <>
            <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap font-mono text-[10px] bg-black/20 dark:bg-black/40 rounded p-1.5 border border-trident-border">
              {preview.system_prompt.slice(0, 1500)}{preview.system_prompt.length > 1500 ? '\n…' : ''}
            </pre>
            <label className="flex items-center gap-1.5 mt-1 text-trident-muted">
              <input type="checkbox" checked={reveal} onChange={(e) => setReveal(e.target.checked)} /> reveal connection values
            </label>
            <div className="font-mono text-[10px] mt-1">
              {Object.entries(preview.env).map(([k, v]) => (
                <div key={k} className="break-all">
                  {k}={/PASSWORD|PASS$/.test(k) && !reveal ? '•'.repeat(10) : v}
                </div>
              ))}
              {Object.keys(preview.env).length === 0 && <span className="text-trident-muted">no env values for this placement</span>}
            </div>
            <div className="mt-1">
              <button
                onClick={() => {
                  const q = (s: string) => `'${String(s).replace(/'/g, `'\\''`)}'`;
                  download(`env-${host.id}.sh`,
                    `# Connection values — ${host.id}\n${Object.entries(preview.env).map(([k, v]) => `export ${k}=${q(v)}`).join('\n')}\n`,
                    'text/x-sh');
                }}
                className="text-[11px] text-trident-accent hover:underline"
              >download env.sh</button>
            </div>
          </>
        )}
      </details>
      <div className="text-[10px] text-trident-muted">
        Note: the generated prompt persists with the topology; the picker selections themselves are editing-session state.
      </div>
    </div>
  );
}

function download(name: string, text: string, type: string) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
}
