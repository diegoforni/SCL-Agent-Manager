import { createContext, useContext, useState, useCallback, useRef, ReactNode } from 'react';
import type { ReplayEvent, ReplayMetadata, ReplayState } from '@/types';
import { pluginRelativePath, pluginWebSocketUrl } from '@/plugin-url';

interface ReplayControls {
  loadReplay: (path: string, runId?: string) => Promise<void>;
  play: (speed?: number) => void;
  pause: () => void;
  seek: (positionMs: number) => void;
  setSpeed: (speed: number) => void;
  togglePlay: () => void;
  stop: () => void;
}

interface ReplayContextValue {
  replay: ReplayState;
  controls: ReplayControls;
  isLoading: boolean;
  error: string | null;
}

const DEFAULT_REPLAY_STATE: ReplayState = {
  replayId: null,
  path: null,
  positionMs: 0,
  durationMs: 0,
  startTimeMs: 0,
  endTimeMs: 0,
  eventCount: 0,
  isPlaying: false,
  speed: 1,
  events: [],
  error: null,
};

const ReplayContext = createContext<ReplayContextValue | undefined>(undefined);

export function ReplayProvider({ children }: { children: ReactNode }) {
  const [replay, setReplay] = useState<ReplayState>(DEFAULT_REPLAY_STATE);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pendingPlayRef = useRef<{ speed: number } | null>(null);

  const loadReplay = useCallback(async (path: string, runId?: string) => {
    setIsLoading(true);
    setError(null);

    // Stop any existing replay
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    try {
      const response = await fetch(pluginRelativePath('/api/replay/load'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...(path ? { path } : {}),
          ...(runId ? { run_id: runId } : {}),
        }),
      });

      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || err.error || 'Failed to load replay');
      }

      const metadata = (await response.json()) as ReplayMetadata;

      setReplay({
        replayId: metadata.replay_id,
        path: metadata.path,
        positionMs: metadata.start_time_ms,
        durationMs: metadata.duration_ms,
        startTimeMs: metadata.start_time_ms,
        endTimeMs: metadata.end_time_ms,
        eventCount: metadata.event_count,
        isPlaying: false,
        speed: 1,
        events: [],  // Start empty, events will be streamed via WebSocket
        error: null,
      });

      // Connect to WebSocket for playback control
      const url = pluginWebSocketUrl(`/api/replay/${metadata.replay_id}/ws`);

      // Add timeout to detect if connection fails
      const connectionTimeout = setTimeout(() => {
        if (wsRef.current?.readyState === WebSocket.CONNECTING) {
          console.error('[ReplayContext] WebSocket connection timeout - still connecting after 5 seconds');
        }
      }, 5000);

      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        clearTimeout(connectionTimeout);
        // If there's a pending play command, execute it now
        if (pendingPlayRef.current !== null) {
          ws.send(JSON.stringify({ type: 'play', speed: pendingPlayRef.current.speed }));
          setReplay((prev) => ({ ...prev, isPlaying: true, speed: pendingPlayRef.current!.speed }));
          pendingPlayRef.current = null;
        }
      };

      ws.onerror = (e) => {
        clearTimeout(connectionTimeout);
        console.error('[ReplayContext] WebSocket error:', e);
      };

      ws.onclose = (e) => {
        clearTimeout(connectionTimeout);
        console.log('[ReplayContext] WebSocket closed:', e.code, e.reason);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);

          switch (msg.type) {
            case 'state':
              setReplay((prev) => ({
                ...prev,
                positionMs: msg.position_ms,
                isPlaying: msg.playing,
                speed: msg.speed,
              }));
              break;
            case 'events':
              setReplay((prev) => {
                const newEvents = msg.events.filter(
                  (ne: ReplayEvent) => !prev.events.some(
                    (ee) => ee.timestamp_ms === ne.timestamp_ms &&
                           ee.source_type === ne.source_type &&
                           JSON.stringify(ee).slice(0, 100) === JSON.stringify(ne).slice(0, 100)
                  )
                );
                const combined = [...prev.events, ...newEvents];
                combined.sort((a, b) => a.timestamp_ms - b.timestamp_ms);
                return { ...prev, events: combined };
              });
              break;
            case 'playback_complete':
              setReplay((prev) => ({ ...prev, isPlaying: false }));
              break;
            case 'error':
              setError(msg.message);
              setReplay((prev) => ({ ...prev, isPlaying: false, error: msg.message }));
              break;
          }
        } catch (e) {
          console.error('Failed to parse replay WebSocket message', e);
        }
      };

    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMsg);
      setReplay({ ...DEFAULT_REPLAY_STATE, error: errorMsg });
    } finally {
      setIsLoading(false);
    }
  }, []);

  const play = useCallback((speed?: number) => {
    const newSpeed = speed ?? replay.speed;

    if (!wsRef.current) {
      console.error('[ReplayContext] Cannot play - no WebSocket');
      return;
    }

    if (wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'play', speed: newSpeed }));
      setReplay((prev) => ({ ...prev, isPlaying: true, speed: newSpeed }));
    } else if (wsRef.current.readyState === WebSocket.CONNECTING) {
      // WebSocket is still connecting, queue the play command
      pendingPlayRef.current = { speed: newSpeed };
    } else {
      console.error('[ReplayContext] Cannot play - WebSocket not connected, state:', wsRef.current.readyState);
    }
  }, [replay.speed]);

  const pause = useCallback(() => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ type: 'pause' }));
    setReplay((prev) => ({ ...prev, isPlaying: false }));
  }, []);

  const seek = useCallback((positionMs: number) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ type: 'seek', position_ms: positionMs }));
    setReplay((prev) => ({ ...prev, positionMs }));
  }, []);

  const setSpeed = useCallback((speed: number) => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    wsRef.current.send(JSON.stringify({ type: 'set_speed', speed }));
    setReplay((prev) => ({ ...prev, speed }));
  }, []);

  const togglePlay = useCallback(() => {
    if (replay.isPlaying) {
      pause();
    } else {
      play(replay.speed);
    }
  }, [replay.isPlaying, replay.speed, play, pause]);

  const stop = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    pendingPlayRef.current = null;
    setReplay(DEFAULT_REPLAY_STATE);
    setError(null);
  }, []);

  const controls: ReplayControls = {
    loadReplay,
    play,
    pause,
    seek,
    setSpeed,
    togglePlay,
    stop,
  };

  const value: ReplayContextValue = {
    replay,
    controls,
    isLoading,
    error,
  };

  return (
    <ReplayContext.Provider value={value}>
      {children}
    </ReplayContext.Provider>
  );
}

export function useReplayContext() {
  const context = useContext(ReplayContext);
  if (!context) {
    throw new Error('useReplayContext must be used within ReplayProvider');
  }
  return context;
}
