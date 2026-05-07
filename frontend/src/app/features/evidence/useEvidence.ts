import { useCallback, useEffect, useMemo, useState } from "react";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { bridge } from "../../integrations/wailsBridge";
import { LRUCache } from "../../utils/lruCache";

const evidenceCache = new LRUCache<string, UnifiedEvidenceRecord[]>(10);

export interface UseEvidenceOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
  modules?: string[];
}

export function useEvidence({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
  modules,
}: UseEvidenceOptions) {
  const [evidence, setEvidence] = useState<UnifiedEvidenceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runRequest, cancel: cancelRequest } = useAbortableRequest();

  const cacheKey = useMemo(
    () => buildEvidenceCacheKey(captureRevision, filePath, totalPackets, modules),
    [captureRevision, filePath, totalPackets, modules],
  );

  const refreshEvidence = useCallback(
    (force = false) => {
      if (!filePath || !backendConnected) {
        cancelRequest();
        setEvidence([]);
        setLoading(false);
        setError("");
        return;
      }
      if (!force && cacheKey && evidenceCache.has(cacheKey)) {
        cancelRequest();
        setEvidence(evidenceCache.get(cacheKey) ?? []);
        setLoading(false);
        setError("");
        return;
      }

      setLoading(true);
      setError("");
      return runRequest({
        request: (signal) => bridge.getEvidenceWithFilter(modules, signal),
        onSuccess: (payload) => {
          if (cacheKey) {
            evidenceCache.set(cacheKey, payload);
          }
          setEvidence(payload);
        },
        onError: (err) => {
          setError(err instanceof Error ? err.message : "统一证据加载失败");
          setEvidence([]);
        },
        onSettled: () => setLoading(false),
      });
    },
    [backendConnected, cacheKey, cancelRequest, filePath, modules, runRequest],
  );

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshEvidence();
  }, [isPreloadingCapture, refreshEvidence]);

  return {
    evidence,
    loading,
    error,
    refreshEvidence,
  };
}

export function buildEvidenceCacheKey(captureRevision: number, filePath: string, totalPackets: number, modules?: string[]) {
  if (!filePath.trim()) return "";
  const base = `${captureRevision}::${filePath}::${totalPackets}`;
  if (modules && modules.length > 0) {
    return `${base}::${[...modules].sort().join(",")}`;
  }
  return base;
}
