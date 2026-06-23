import { useCallback, useEffect, useRef, useState } from "react";
import type { AnalysisResourceCache } from "../core/analysisResourceCache";
import { useAbortableRequest } from "./useAbortableRequest";

export interface UseAnalysisResultOptions<T> {
  cache: AnalysisResourceCache<T>;
  cacheKey: string;
  emptyValue: T;
  enabled: boolean;
  isPreloadingCapture: boolean;
  errorMessage: string;
  fetch: (signal: AbortSignal, force?: boolean) => Promise<T>;
  onSuccess?: (payload: T) => void;
}

export interface UseAnalysisResult<T> {
  data: T;
  loading: boolean;
  error: string;
  refresh: (force?: boolean) => (() => void) | undefined;
}

export function useAnalysisResult<T>({
  cache,
  cacheKey,
  emptyValue,
  enabled,
  isPreloadingCapture,
  errorMessage,
  fetch,
  onSuccess,
}: UseAnalysisResultOptions<T>): UseAnalysisResult<T> {
  const [data, setData] = useState<T>(emptyValue);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run, cancel } = useAbortableRequest();

  // Keep the latest fetch/success callbacks without destabilising the refresh
  // callback. Callers often pass a fresh inline arrow for fetch, which would
  // otherwise cause the auto-fetch effect to cycle on every render.
  const fetchRef = useRef(fetch);
  fetchRef.current = fetch;
  const onSuccessRef = useRef(onSuccess);
  onSuccessRef.current = onSuccess;

  const refresh = useCallback(
    (force = false) => {
      if (!enabled || !cacheKey) {
        cancel();
        setData(emptyValue);
        setLoading(false);
        setError("");
        return;
      }

      if (!force && cache.has(cacheKey)) {
        cancel();
        setData(cache.get(cacheKey) ?? emptyValue);
        setLoading(false);
        setError("");
        return;
      }

      setLoading(true);
      setError("");
      return run({
        request: (signal) =>
          cache.request(cacheKey, {
            force,
            signal,
            load: () => fetchRef.current(signal, force),
          }),
        onSuccess: (payload) => {
          if (cacheKey) {
            cache.set(cacheKey, payload);
          }
          setData(payload);
          onSuccessRef.current?.(payload);
        },
        onError: (err) => {
          setError(err instanceof Error ? err.message : errorMessage);
          setData(emptyValue);
        },
        onSettled: () => setLoading(false),
      });
    },
    [cache, cacheKey, cancel, emptyValue, enabled, errorMessage, run],
  );

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refresh();
  }, [isPreloadingCapture, refresh]);

  return { data, loading, error, refresh };
}
