import { useState, useEffect } from 'react';
import { pluginRelativePath } from '@/plugin-url';

/**
 * Hook for listing available replay runs.
 *
 * (The previous `useReplay()` playback hook that lived in this file was dead —
 * `ReplayContext` reimplemented the same logic and owns the single replay WS —
 * so it was removed during WS-ownership consolidation.)
 */
export function useReplayRuns() {
  const [runs, setRuns] = useState<Array<{ run_id: string; path: string; is_current: boolean; created: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRuns = async () => {
    try {
      setLoading(true);
      const response = await fetch(pluginRelativePath('/api/replay/runs'));
      if (!response.ok) throw new Error('Failed to fetch runs');
      const data = await response.json();
      setRuns(data.runs || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRuns();
  }, []);

  return { runs, loading, error, refetch: fetchRuns };
}
