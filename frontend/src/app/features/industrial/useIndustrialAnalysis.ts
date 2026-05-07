import { useCallback, useEffect, useMemo, useState } from "react";
import type { IndustrialAnalysis as IndustrialAnalysisData } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { bridge } from "../../integrations/wailsBridge";

export const EMPTY_INDUSTRIAL_ANALYSIS: IndustrialAnalysisData = {
  totalIndustrialPackets: 0,
  protocols: [],
  conversations: [],
  modbus: {
    totalFrames: 0,
    requests: 0,
    responses: 0,
    exceptions: 0,
    functionCodes: [],
    unitIds: [],
    referenceHits: [],
    exceptionCodes: [],
    transactions: [],
    decodedInputs: [],
  },
  ruleHits: [],
  details: [],
  notes: [],
};

const industrialAnalysisCache = new Map<string, IndustrialAnalysisData>();

export interface UseIndustrialAnalysisOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
}

export function useIndustrialAnalysis({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
}: UseIndustrialAnalysisOptions) {
  const cacheKey = useMemo(() => buildIndustrialAnalysisCacheKey(captureRevision, filePath, totalPackets), [captureRevision, filePath, totalPackets]);
  const [analysis, setAnalysis] = useState<IndustrialAnalysisData>(EMPTY_INDUSTRIAL_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      cancelAnalysisRequest();
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_INDUSTRIAL_ANALYSIS);
      return;
    }
    if (!force && cacheKey && industrialAnalysisCache.has(cacheKey)) {
      cancelAnalysisRequest();
      setAnalysis(industrialAnalysisCache.get(cacheKey) ?? EMPTY_INDUSTRIAL_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    return runAnalysisRequest({
      request: (signal) => bridge.getIndustrialAnalysis(signal),
      onSuccess: (payload) => {
        if (cacheKey) {
          industrialAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      },
      onError: (err) => {
        setError(err instanceof Error ? err.message : "工控分析加载失败");
        setAnalysis(EMPTY_INDUSTRIAL_ANALYSIS);
      },
      onSettled: () => setLoading(false),
    });
  }, [backendConnected, cacheKey, cancelAnalysisRequest, runAnalysisRequest]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return { analysis, loading, error, refreshAnalysis };
}

export function buildIndustrialAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}
