import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { pluginWebSocketUrl } from '@/plugin-url';
import type { TimelineEntry, ReplayEvent } from '@/types';
import { getTimeline } from '@/api';
import { useReplayContext } from '@/contexts/ReplayContext';

/** Map agent keys to their expected source file paths */
const AGENT_SOURCE_PATTERNS: Record<string, string[]> = {
  coder56: ['coder56/'],
  db_admin: ['benign_agent/db_admin'],
  soc_god: ['soc_god/'],
};

/** Convert replay events to TimelineEntry format */
function replayEventsToTimelineEntries(events: ReplayEvent[], agent: string, positionMs: number, startTimeMs: number): TimelineEntry[] {
  const entries: TimelineEntry[] = [];

  // Get the source patterns for this agent
  const sourcePatterns = AGENT_SOURCE_PATTERNS[agent] || [];

  // Calculate the window: show events from startTimeMs up to positionMs + 60 seconds
  const windowEndMs = positionMs + 60000; // 60 second look-ahead window

  console.log(`[useTimelineStream] ${agent}: Converting ${events.length} events, startTimeMs=${startTimeMs}, positionMs=${positionMs}, windowEndMs=${windowEndMs}`);

  for (const event of events) {
    // Filter by playback position window
    if (event.timestamp_ms < startTimeMs || event.timestamp_ms > windowEndMs) {
      continue;
    }

    // Filter by source file path for the agent
    const sourceFile = event.source_file || '';
    const matchesAgent = sourcePatterns.some(pattern => sourceFile.includes(pattern));
    if (!matchesAgent) {
      continue;
    }

    // Include valid timeline events
    const isValidTimelineEvent =
      event.source_type === 'timeline' ||
      (event.source_type === 'opencode' && event.level) ||
      event.source_type === 'alert';

    if (!isValidTimelineEvent) {
      continue;
    }

    const entry: TimelineEntry = {
      ts: event.ts || new Date(event.timestamp_ms).toISOString(),
      level: (event.level as string | undefined) ||
             (event.source_type === 'alert' ? 'ALERT' : 'INFO'),
      msg: event.msg || '',
      exec: event.exec as string | undefined,
      data: event.data,
    };

    entries.push(entry);
  }

  console.log(`[useTimelineStream] ${agent}: Filtered to ${entries.length} entries`);

  // Filter out step_start/step_finish entries
  return entries.filter((e) => {
    const type = e.data?.type as string;
    return !(
      e.level === 'OPENCODE' &&
      (type === 'step_start' || type === 'step-start' || type === 'step_finish' || type === 'step-finish')
    );
  });
}

/**
 * Live timeline stream for an agent.
 * When a replay is active, returns data from the replay instead of live data.
 */
export function useTimelineStream(agent: string) {
  const { replay } = useReplayContext();
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const backoffRef = useRef(1000);
  const replayIdRef = useRef<string | null>(replay.replayId);

  replayIdRef.current = replay.replayId;
  const isReplayActive = replay.replayId !== null;

  console.log(`[useTimelineStream] ${agent} render: replayId=${replay.replayId}, events.length=${replay.events.length}`);

  // Convert replay events when active
  const replayEntries = useMemo(() => {
    if (!isReplayActive) return null;
    return replayEventsToTimelineEntries(replay.events, agent, replay.positionMs, replay.startTimeMs);
  }, [isReplayActive, replay.events, agent, replay.positionMs, replay.startTimeMs]);

  // Update state from replay data
  useEffect(() => {
    if (replay.replayId !== null && replayEntries) {
      setEntries(replayEntries);
      setConnected(true);
    }
  }, [replayEntries, replay.replayId, agent]);

  // REST poll every 3s (only when not in replay mode)
  useEffect(() => {
    if (replay.replayId !== null) return;

    let cancelled = false;

    const load = () => {
      getTimeline(agent)
        .then((r) => {
          if (cancelled) return;
          const fetched: TimelineEntry[] = r?.entries ?? [];
          setEntries((prev) => (fetched.length > prev.length ? fetched : prev));
        })
        .catch(() => {});
    };

    load();
    const interval = setInterval(load, 3_000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [agent, replay.replayId]);

  // WebSocket live stream (only when not in replay mode)
  const connect = useCallback(() => {
    if (replay.replayId !== null) return;

    const url = pluginWebSocketUrl(`/api/timeline/${agent}/ws`);
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      backoffRef.current = 1000;
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'timeline' && msg.full && Array.isArray(msg.data)) {
          setEntries(msg.data as TimelineEntry[]);
        }
      } catch {}
    };

    ws.onclose = () => {
      if (replayIdRef.current === null) {
        setConnected(false);
        const delay = backoffRef.current;
        backoffRef.current = Math.min(delay * 2, 30000);
        reconnectTimer.current = setTimeout(connect, delay);
      }
    };
    ws.onerror = () => ws.close();
  }, [agent]);

  useEffect(() => {
    if (replay.replayId === null) {
      connect();
    }
    return () => {
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect, replay.replayId]);

  return { entries, connected, isReplayActive };
}
