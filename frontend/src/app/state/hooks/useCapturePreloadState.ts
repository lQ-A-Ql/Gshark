import { useRef, useState, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import { useSyncedRefValue } from "./useSyncedRefValue";

export interface UseCapturePreloadStateResult {
  readonly isPreloadingCapture: boolean;
  readonly preloadProcessed: number;
  readonly preloadTotal: number;
  readonly preloadProcessedRef: MutableRefObject<number>;
  readonly preloadTotalRef: MutableRefObject<number>;
  readonly setIsPreloadingCapture: Dispatch<SetStateAction<boolean>>;
  readonly setPreloadProcessed: Dispatch<SetStateAction<number>>;
  readonly setPreloadTotal: Dispatch<SetStateAction<number>>;
}

/**
 * Owns the preload/parsing progress state slice.
 *
 * The refs are kept in sync with the useState values so callers that need
 * synchronous ref access (for example `capturePreloadProbe`) can continue
 * reading the latest values without re-renders.
 */
export function useCapturePreloadState(): UseCapturePreloadStateResult {
  const [isPreloadingCapture, setIsPreloadingCapture] = useState(false);
  const [preloadProcessed, setPreloadProcessed] = useState(0);
  const [preloadTotal, setPreloadTotal] = useState(0);

  const preloadProcessedRef = useRef(preloadProcessed);
  const preloadTotalRef = useRef(preloadTotal);

  useSyncedRefValue(preloadProcessedRef, preloadProcessed);
  useSyncedRefValue(preloadTotalRef, preloadTotal);

  return {
    isPreloadingCapture,
    preloadProcessed,
    preloadTotal,
    preloadProcessedRef,
    preloadTotalRef,
    setIsPreloadingCapture,
    setPreloadProcessed,
    setPreloadTotal,
  };
}
