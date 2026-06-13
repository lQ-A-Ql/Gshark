import { useCallback, useEffect, useMemo, useState } from "react";
import type { APTAnalysis } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { backendClients } from "../../integrations/backendClients";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";
import { buildAPTDisplayProfiles } from "./actorRegistry";

export const EMPTY_APT_ANALYSIS: APTAnalysis = {
  totalEvidence: 0,
  actors: [],
  sampleFamilies: [],
  campaignStages: [],
  transportTraits: [],
  infrastructureHints: [],
  relatedC2Families: [],
  profiles: [],
  evidence: [],
  notes: [],
};

const aptAnalysisCache = createAnalysisResourceCache<APTAnalysis>({ capacity: 10 });

export interface UseAPTAnalysisOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
  activeActorId: string;
  onActiveActorChange: (actorId: string) => void;
}

export function useAPTAnalysis({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
  activeActorId,
  onActiveActorChange,
}: UseAPTAnalysisOptions) {
  const [analysis, setAnalysis] = useState<APTAnalysis>(EMPTY_APT_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const cacheKey = useMemo(
    () => buildAPTAnalysisCacheKey(captureRevision, filePath, totalPackets),
    [captureRevision, filePath, totalPackets],
  );

  const refreshAnalysis = useCallback(
    (force = false) => {
      if (!backendConnected || !hasUsableCapturePath(filePath, totalPackets)) {
        cancelAnalysisRequest();
        setAnalysis(EMPTY_APT_ANALYSIS);
        setLoading(false);
        setError("");
        return;
      }
      if (!force && cacheKey && aptAnalysisCache.has(cacheKey)) {
        cancelAnalysisRequest();
        setAnalysis(aptAnalysisCache.get(cacheKey) ?? EMPTY_APT_ANALYSIS);
        setLoading(false);
        setError("");
        return;
      }

      setLoading(true);
      setError("");
      return runAnalysisRequest({
        request: (signal) =>
          aptAnalysisCache.request(cacheKey, {
            force,
            signal,
            load: () => backendClients.analysis.getAPTAnalysis(signal),
          }),
        onSuccess: (payload) => {
          if (cacheKey) {
            aptAnalysisCache.set(cacheKey, payload);
          }
          setAnalysis(payload);
          const nextProfiles = buildAPTDisplayProfiles(payload.profiles);
          if (nextProfiles.length > 0 && !nextProfiles.some((profile) => profile.id === activeActorId)) {
            onActiveActorChange(nextProfiles[0].id);
          }
        },
        onError: (err) => {
          setError(err instanceof Error ? err.message : "APT 组织画像加载失败");
          setAnalysis(EMPTY_APT_ANALYSIS);
        },
        onSettled: () => setLoading(false),
      });
    },
    [
      activeActorId,
      backendConnected,
      cacheKey,
      cancelAnalysisRequest,
      filePath,
      onActiveActorChange,
      runAnalysisRequest,
      totalPackets,
    ],
  );

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return {
    analysis,
    loading,
    error,
    refreshAnalysis,
  };
}

export function buildAPTAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}
