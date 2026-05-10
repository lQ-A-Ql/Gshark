import { useCallback, useRef } from "react";
import { prepareCaptureReplacementState } from "../captureReplacementPrepare";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

type UseCaptureReplacementPrepareOptions = {
  readonly backendConnected: boolean;
  readonly parseFinishedRef: Ref<boolean>;
  readonly parseErrorRef: Ref<string>;
  readonly preloadingRef: Ref<boolean>;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly cancelAllFrontendCaptureTasks: () => void;
  readonly wakeCaptureWaiters: () => void;
  readonly setIsPreloadingCapture: Setter<boolean>;
  readonly setIsFilterLoading: Setter<boolean>;
  readonly setPreloadProcessed: Setter<number>;
  readonly setPreloadTotal: Setter<number>;
  readonly stopStreamingPackets: () => Promise<unknown>;
  readonly prepareCaptureReplacement: () => Promise<unknown>;
};

export function useCaptureReplacementPrepare(options: UseCaptureReplacementPrepareOptions) {
  const optionsRef = useRef(options);
  optionsRef.current = options;

  return useCallback(async () => {
    await prepareCaptureReplacementState(optionsRef.current);
  }, []);
}
