import { useMemo } from "react";
import type { IndustrialAnalysis as IndustrialAnalysisData } from "../../core/types";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";
import { backendClients } from "../../integrations/backendClients";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";

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
  report: EMPTY_INVESTIGATION_REPORT,
};

const industrialAnalysisCache = createAnalysisResourceCache<IndustrialAnalysisData>();

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
  const cacheKey = useMemo(
    () => buildIndustrialAnalysisCacheKey(captureRevision, filePath, totalPackets),
    [captureRevision, filePath, totalPackets],
  );

  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data, loading, error, refresh } = useAnalysisResult<IndustrialAnalysisData>({
    cache: industrialAnalysisCache,
    cacheKey,
    emptyValue: EMPTY_INDUSTRIAL_ANALYSIS,
    enabled,
    isPreloadingCapture,
    errorMessage: "工控分析加载失败",
    fetch: (signal) => backendClients.analysis.getIndustrialAnalysis(signal),
  });

  return { analysis: data, loading, error, refreshAnalysis: refresh };
}

export function buildIndustrialAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}
