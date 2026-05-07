import { useCallback, useEffect, useState } from "react";
import { useSentinel } from "../../state/SentinelContext";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";

export interface UseMiscModuleAnalysisOptions<T> {
  fetch: (signal: AbortSignal) => Promise<T>;
  emptyData: T;
  errorMessage?: string;
}

export function useMiscModuleAnalysis<T>({
  fetch,
  emptyData,
  errorMessage = "加载分析失败",
}: UseMiscModuleAnalysisOptions<T>) {
  const { fileMeta } = useSentinel();
  const hasCapture = Boolean(fileMeta.path);
  const [analysis, setAnalysis] = useState<T>(emptyData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const { run, cancel } = useAbortableRequest();

  const loadAnalysis = useCallback(() => {
    if (!hasCapture) {
      cancel();
      setAnalysis(emptyData);
      setError("");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    return run({
      request: (signal) => fetch(signal),
      onSuccess: (payload) => setAnalysis(payload),
      onError: (err) => {
        setAnalysis(emptyData);
        setError(err instanceof Error ? err.message : errorMessage);
      },
      onSettled: () => setLoading(false),
    });
  }, [cancel, emptyData, errorMessage, fetch, hasCapture, run]);

  useEffect(() => loadAnalysis(), [fileMeta.path, loadAnalysis]);

  const refresh = useCallback(() => loadAnalysis(), [loadAnalysis]);

  return { analysis, setAnalysis, loading, error, refresh };
}
