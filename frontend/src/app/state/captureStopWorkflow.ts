import { finishCaptureParseRuntime } from "./captureParseRuntimeState";
import {
  getCaptureCloseErrorMessage,
  getCaptureStopDoneStatus,
  getCaptureStopRequestStatus,
} from "./captureStopStatus";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

export interface StopCaptureWorkflowOptions {
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
}

export async function stopCaptureWorkflow(options: StopCaptureWorkflowOptions): Promise<void> {
  options.captureSeqRef.current += 1;
  options.filterSeqRef.current += 1;
  finishCaptureParseRuntime({
    parseFinishedRef: options.parseFinishedRef,
    parseErrorRef: options.parseErrorRef,
    preloadingRef: options.preloadingRef,
    setIsPreloadingCapture: options.setIsPreloadingCapture,
  });
  options.setIsFilterLoading(false);
  options.cancelAllFrontendCaptureTasks();
  options.wakeCaptureWaiters();
  options.clearCaptureUiState();
  options.threatAnalysisSeqRef.current += 1;
  options.setBackendStatus(getCaptureStopRequestStatus(options.backendConnected));
  if (!options.backendConnected) return;

  let closeError = "";
  try {
    await options.cancelMediaBatchTranscription().catch(() => null);
    await options.closeCapture();
  } catch (error) {
    closeError = getCaptureCloseErrorMessage(error);
  }
  options.setBackendStatus(getCaptureStopDoneStatus(closeError));
}
