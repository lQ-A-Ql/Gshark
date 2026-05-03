import { useCallback, useEffect, useMemo, useState } from "react";
import type { C2FamilyAnalysis, C2SampleAnalysis } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { bridge } from "../../integrations/wailsBridge";
import { LRUCache } from "../../utils/lruCache";

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
};

export const EMPTY_C2_ANALYSIS: C2SampleAnalysis = {
  totalMatchedPackets: 0,
  families: [],
  conversations: [],
  cs: EMPTY_FAMILY,
  vshell: EMPTY_FAMILY,
  notes: [],
};

const c2AnalysisCache = new LRUCache<string, C2SampleAnalysis>(10);

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
  const [analysis, setAnalysis] = useState<C2SampleAnalysis>(EMPTY_C2_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const cacheKey = useMemo(() => buildC2SampleAnalysisCacheKey(captureRevision, filePath, totalPackets), [captureRevision, filePath, totalPackets]);

  const refreshAnalysis = useCallback((force = false) => {
    if (!filePath || !backendConnected) {
      cancelAnalysisRequest();
      setAnalysis(EMPTY_C2_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    if (!force && cacheKey && c2AnalysisCache.has(cacheKey)) {
      cancelAnalysisRequest();
      setAnalysis(c2AnalysisCache.get(cacheKey) ?? EMPTY_C2_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }

    setLoading(true);
    setError("");
    return runAnalysisRequest({
      request: (signal) => bridge.getC2SampleAnalysis(signal),
      onSuccess: (payload) => {
        if (cacheKey) {
          c2AnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      },
      onError: (err) => {
        setError(err instanceof Error ? err.message : "C2 样本分析加载失败");
        setAnalysis(EMPTY_C2_ANALYSIS);
      },
      onSettled: () => setLoading(false),
    });
  }, [backendConnected, cacheKey, cancelAnalysisRequest, filePath, runAnalysisRequest]);

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

export function buildC2SampleAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  if (!filePath.trim()) return "";
  return `${captureRevision}::${filePath}::${totalPackets}`;
}
