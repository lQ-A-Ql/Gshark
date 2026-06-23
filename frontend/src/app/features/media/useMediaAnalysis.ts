import { useMemo, useState } from "react";
import type { MediaAnalysis as MediaAnalysisData, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";

export const EMPTY_MEDIA_ANALYSIS: MediaAnalysisData = {
  totalMediaPackets: 0,
  protocols: [],
  applications: [],
  sessions: [],
  notes: [],
};

export const EMPTY_BATCH_STATUS: SpeechBatchTaskStatus = {
  taskId: "",
  total: 0,
  queued: 0,
  running: 0,
  completed: 0,
  failed: 0,
  skipped: 0,
  done: false,
  cancelled: false,
  items: [],
};

const mediaAnalysisCache = createAnalysisResourceCache<MediaAnalysisData>();

export interface UseMediaAnalysisOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
}

export function useMediaAnalysis({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
}: UseMediaAnalysisOptions) {
  const cacheKey = useMemo(
    () => buildMediaAnalysisCacheKey(captureRevision, filePath, totalPackets),
    [captureRevision, filePath, totalPackets],
  );
  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data: analysis, loading, error, refresh: refreshAnalysis } = useAnalysisResult<MediaAnalysisData>({
    cache: mediaAnalysisCache,
    cacheKey,
    emptyValue: EMPTY_MEDIA_ANALYSIS,
    enabled,
    isPreloadingCapture,
    errorMessage: "媒体分析加载失败",
    fetch: (signal, force) => backendClients.media.getMediaAnalysis(force, signal),
  });

  const [batchStatus, setBatchStatus] = useState<SpeechBatchTaskStatus>(EMPTY_BATCH_STATUS);
  const [transcriptions, setTranscriptions] = useState<Record<string, MediaTranscription>>({});

  return {
    analysis,
    loading,
    error,
    refreshAnalysis,
    batchStatus,
    setBatchStatus,
    transcriptions,
    setTranscriptions,
  };
}

export function buildMediaAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}
