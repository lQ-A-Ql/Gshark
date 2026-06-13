import { useCallback, useEffect, useMemo, useState } from "react";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { backendClients } from "../../integrations/backendClients";
import type { FeaturePreloadContract } from "../../preload/preloadContracts";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";

const evidenceCache = createAnalysisResourceCache<UnifiedEvidenceRecord[]>({ capacity: 10 });
const EMPTY_EVIDENCE: UnifiedEvidenceRecord[] = [];

export interface UseEvidenceOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
  modules?: string[];
}

export type EvidencePreloadInput = Pick<
  UseEvidenceOptions,
  "backendConnected" | "filePath" | "totalPackets" | "captureRevision" | "modules"
>;

export function useEvidence({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
  modules,
}: UseEvidenceOptions) {
  const modulesKey = buildEvidenceModulesKey(modules);
  const normalizedModules = useMemo(() => parseEvidenceModulesKey(modulesKey), [modulesKey]);
  const hasCaptureForEvidence = useMemo(
    () => backendConnected && hasUsableCapturePath(filePath, totalPackets),
    [backendConnected, filePath, totalPackets],
  );
  const [evidence, setEvidence] = useState<UnifiedEvidenceRecord[]>(EMPTY_EVIDENCE);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runRequest, cancel: cancelRequest } = useAbortableRequest();

  const cacheKey = useMemo(
    () => buildEvidenceCacheKey(captureRevision, filePath, totalPackets, normalizedModules),
    [captureRevision, filePath, normalizedModules, totalPackets],
  );

  const refreshEvidence = useCallback(
    (force = false) => {
      if (!hasCaptureForEvidence) {
        cancelRequest();
        setEvidence(EMPTY_EVIDENCE);
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
        request: (signal) => requestEvidence(cacheKey, normalizedModules, signal, { force }),
        onSuccess: (payload) => {
          if (cacheKey) {
            evidenceCache.set(cacheKey, payload);
          }
          setEvidence(payload);
        },
        onError: (err) => {
          setError(err instanceof Error ? err.message : "统一证据加载失败");
          setEvidence(EMPTY_EVIDENCE);
        },
        onSettled: () => setLoading(false),
      });
    },
    [cacheKey, cancelRequest, hasCaptureForEvidence, normalizedModules, runRequest],
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

export function buildEvidenceCacheKey(
  captureRevision: number,
  filePath: string,
  totalPackets: number,
  modules?: string[],
) {
  if (!filePath.trim() || totalPackets <= 0) return "";
  const base = `${captureRevision}::${filePath}::${totalPackets}`;
  const modulesKey = buildEvidenceModulesKey(modules);
  if (modulesKey) {
    return `${base}::${modulesKey}`;
  }
  return base;
}

export function buildEvidenceModulesKey(modules?: readonly string[]) {
  if (!modules || modules.length === 0) return "";
  return Array.from(new Set(modules.map((module) => module.trim()).filter(Boolean)))
    .sort()
    .join(",");
}

function parseEvidenceModulesKey(modulesKey: string) {
  return modulesKey ? modulesKey.split(",") : undefined;
}

export const evidencePreloadContract: FeaturePreloadContract<EvidencePreloadInput, UnifiedEvidenceRecord[]> = {
  getCacheKey(input) {
    return buildEvidenceCacheKey(input.captureRevision, input.filePath, input.totalPackets, input.modules);
  },
  readCache(key) {
    return evidenceCache.get(key);
  },
  writeCache(key, data) {
    if (key) evidenceCache.set(key, data);
  },
  getInflight(key) {
    return evidenceCache.getInflight(key);
  },
  prefetch(input, signal) {
    if (!input.backendConnected || !hasUsableCapturePath(input.filePath, input.totalPackets))
      return Promise.resolve([]);
    if (!input.modules || input.modules.length === 0) {
      return Promise.reject(new Error("evidence preload requires explicit modules"));
    }
    const cacheKey = evidencePreloadContract.getCacheKey(input);
    return requestEvidence(cacheKey, input.modules, signal, { force: false });
  },
};

export function resetEvidencePreloadForTest() {
  evidenceCache.clear();
}

function requestEvidence(
  cacheKey: string,
  modules: string[] | undefined,
  signal: AbortSignal,
  options: { force: boolean },
): Promise<UnifiedEvidenceRecord[]> {
  return evidenceCache.request(cacheKey, {
    force: options.force,
    signal,
    load: () => backendClients.evidence.getEvidenceWithFilter(modules, signal),
  });
}
