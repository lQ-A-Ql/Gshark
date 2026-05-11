import { useCallback, useRef } from "react";
import { stopCaptureWorkflow } from "../captureStopWorkflow";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

type UseCaptureStopWorkflowOptions = {
  readonly backendConnected: boolean;
  readonly captureSeqRef: Ref<number>;
  readonly filterSeqRef: Ref<number>;
  readonly threatAnalysisSeqRef: Ref<number>;
  readonly parseFinishedRef: Ref<boolean>;
  readonly parseErrorRef: Ref<string>;
  readonly preloadingRef: Ref<boolean>;
  readonly setIsPreloadingCapture: Setter<boolean>;
  readonly setIsFilterLoading: Setter<boolean>;
  readonly cancelAllFrontendCaptureTasks: () => void;
  readonly wakeCaptureWaiters: () => void;
  readonly clearCaptureUiState: () => void;
  readonly setBackendStatus: (status: string) => void;
  readonly cancelMediaBatchTranscription: () => Promise<unknown>;
  readonly closeCapture: () => Promise<unknown>;
};

export function useCaptureStopWorkflow(options: UseCaptureStopWorkflowOptions) {
  const optionsRef = useRef(options);
  optionsRef.current = options;

  return useCallback(async () => {
    await stopCaptureWorkflow(optionsRef.current);
  }, []);
}
