import { useCallback, useEffect, useMemo, useState } from "react";
import type { MediaAnalysis as MediaAnalysisData, MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { bridge } from "../../integrations/wailsBridge";

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

const mediaAnalysisCache = new Map<string, MediaAnalysisData>();

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
  const cacheKey = useMemo(() => buildMediaAnalysisCacheKey(captureRevision, filePath, totalPackets), [captureRevision, filePath, totalPackets]);
  const [analysis, setAnalysis] = useState<MediaAnalysisData>(EMPTY_MEDIA_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [batchStatus, setBatchStatus] = useState<SpeechBatchTaskStatus>(EMPTY_BATCH_STATUS);
  const [transcriptions, setTranscriptions] = useState<Record<string, MediaTranscription>>({});
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      cancelAnalysisRequest();
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_MEDIA_ANALYSIS);
      return;
    }
    if (!force && cacheKey && mediaAnalysisCache.has(cacheKey)) {
      cancelAnalysisRequest();
      setAnalysis(mediaAnalysisCache.get(cacheKey) ?? EMPTY_MEDIA_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    return runAnalysisRequest({
      request: (signal) => bridge.getMediaAnalysis(false, signal),
      onSuccess: (payload) => {
        if (cacheKey) {
          mediaAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      },
      onError: (err) => {
        setError(err instanceof Error ? err.message : "媒体分析加载失败");
        setAnalysis(EMPTY_MEDIA_ANALYSIS);
      },
      onSettled: () => setLoading(false),
    });
  }, [backendConnected, cacheKey, cancelAnalysisRequest, runAnalysisRequest]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

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
