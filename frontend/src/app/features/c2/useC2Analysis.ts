import { useMemo } from "react";
import type { C2FamilyAnalysis, C2SampleAnalysis } from "../../core/types";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";
import { backendClients } from "../../integrations/backendClients";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";

const EMPTY_FAMILY: C2FamilyAnalysis = {
  candidateCount: 0,
  matchedRuleCount: 0,
  channels: [],
  indicators: [],
  conversations: [],
  beaconPatterns: [],
  hostUriAggregates: [],
  dnsAggregates: [],
  streamAggregates: [],
  candidates: [],
  notes: [],
  relatedActors: [],
  deliveryChains: [],
  report: EMPTY_INVESTIGATION_REPORT,
};

export const EMPTY_C2_ANALYSIS: C2SampleAnalysis = {
  totalMatchedPackets: 0,
  families: [],
  conversations: [],
  cs: EMPTY_FAMILY,
  vshell: EMPTY_FAMILY,
  notes: [],
};

const c2AnalysisCache = createAnalysisResourceCache<C2SampleAnalysis>({ capacity: 10 });

export interface UseC2AnalysisOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
}

export function useC2Analysis({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
}: UseC2AnalysisOptions) {
  const cacheKey = useMemo(
    () => buildC2SampleAnalysisCacheKey(captureRevision, filePath, totalPackets),
    [captureRevision, filePath, totalPackets],
  );

  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data, loading, error, refresh } = useAnalysisResult<C2SampleAnalysis>({
    cache: c2AnalysisCache,
    cacheKey,
    emptyValue: EMPTY_C2_ANALYSIS,
    enabled,
    isPreloadingCapture,
    errorMessage: "C2 样本分析加载失败",
    fetch: (signal) => backendClients.analysis.getC2SampleAnalysis(signal),
  });

  return {
    analysis: data,
    loading,
    error,
    refreshAnalysis: refresh,
  };
}

export function buildC2SampleAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  if (!filePath.trim()) return "";
  return `${captureRevision}::${filePath}::${totalPackets}`;
}
