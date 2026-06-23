import { useMemo } from "react";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { backendClients } from "../../integrations/backendClients";
import type { FeaturePreloadContract } from "../../preload/preloadContracts";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";

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
  const cacheKey = useMemo(
    () => buildEvidenceCacheKey(captureRevision, filePath, totalPackets, normalizedModules),
    [captureRevision, filePath, normalizedModules, totalPackets],
  );
  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data: evidence, loading, error, refresh: refreshEvidence } = useAnalysisResult<UnifiedEvidenceRecord[]>({
    cache: evidenceCache,
    cacheKey,
    emptyValue: EMPTY_EVIDENCE,
    enabled,
    isPreloadingCapture,
    errorMessage: "统一证据加载失败",
    fetch: (signal) => backendClients.evidence.getEvidenceWithFilter(normalizedModules, signal),
  });

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
