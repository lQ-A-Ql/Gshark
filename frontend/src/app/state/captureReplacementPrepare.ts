import { finishCaptureParseRuntime } from "./captureParseRuntimeState";
import { resetPreloadCounterState } from "./captureResetState";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

export interface PrepareCaptureReplacementOptions {
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
}

export async function prepareCaptureReplacementState(options: PrepareCaptureReplacementOptions): Promise<void> {
  options.cancelAllFrontendCaptureTasks();
  options.wakeCaptureWaiters();
  finishCaptureParseRuntime({
    parseFinishedRef: options.parseFinishedRef,
    parseErrorRef: options.parseErrorRef,
    preloadingRef: options.preloadingRef,
    setIsPreloadingCapture: options.setIsPreloadingCapture,
  });
  options.setIsFilterLoading(false);
  resetPreloadCounterState({
    preloadProcessedRef: options.preloadProcessedRef,
    preloadTotalRef: options.preloadTotalRef,
    setPreloadProcessed: options.setPreloadProcessed,
    setPreloadTotal: options.setPreloadTotal,
  });

  if (!options.backendConnected) return;
  await options.stopStreamingPackets().catch(() => null);
  await options.prepareCaptureReplacement().catch(() => null);
}
