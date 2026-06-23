import { useMemo } from "react";
import type { APTAnalysis } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";
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
  const cacheKey = useMemo(
    () => buildAPTAnalysisCacheKey(captureRevision, filePath, totalPackets),
    [captureRevision, filePath, totalPackets],
  );
  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data: analysis, loading, error, refresh: refreshAnalysis } = useAnalysisResult<APTAnalysis>({
    cache: aptAnalysisCache,
    cacheKey,
    emptyValue: EMPTY_APT_ANALYSIS,
    enabled,
    isPreloadingCapture,
    errorMessage: "APT 组织画像加载失败",
    fetch: (signal) => backendClients.analysis.getAPTAnalysis(signal),
    onSuccess: (payload) => {
      const nextProfiles = buildAPTDisplayProfiles(payload.profiles);
      if (nextProfiles.length > 0 && !nextProfiles.some((profile) => profile.id === activeActorId)) {
        onActiveActorChange(nextProfiles[0].id);
      }
    },
  });

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
