import type { CaptureTransactionStatus } from "./sentinelTypes";
import type { OpenedCapture } from "./captureOpenState";
import { buildRecentCapture } from "./captureOpenState";
import { startCaptureParseRuntime } from "./captureParseRuntimeState";
import { resetPreloadCounterState } from "./captureResetState";
import { createPendingCaptureTransactionStatus } from "./captureTransactionStatus";

type Ref<T> = { current: T };
type Setter<T> = (value: T | ((prev: T) => T)) => void;

interface CaptureStartStateOptions {
  readonly opened: OpenedCapture;
  readonly openedAt: string;
  readonly hadActiveCapture: boolean;
  readonly preloadProcessedRef: Ref<number>;
  readonly preloadTotalRef: Ref<number>;
  readonly parseFinishedRef: Ref<boolean>;
  readonly parseErrorRef: Ref<string>;
  readonly preloadingRef: Ref<boolean>;
  readonly setIsFilterLoading: Setter<boolean>;
  readonly setPacketPageError: Setter<string>;
  readonly setPreloadProcessed: Setter<number>;
  readonly setPreloadTotal: Setter<number>;
  readonly setIsPreloadingCapture: Setter<boolean>;
  readonly setCaptureTransaction: Setter<CaptureTransactionStatus>;
  readonly rememberRecentCapture: (capture: ReturnType<typeof buildRecentCapture>) => void;
}

export function initializeCaptureStartState({
  opened,
  openedAt,
  hadActiveCapture,
  preloadProcessedRef,
  preloadTotalRef,
  parseFinishedRef,
  parseErrorRef,
  preloadingRef,
  setIsFilterLoading,
  setPacketPageError,
  setPreloadProcessed,
  setPreloadTotal,
  setIsPreloadingCapture,
  setCaptureTransaction,
  rememberRecentCapture,
}: CaptureStartStateOptions): void {
  setIsFilterLoading(false);
  setPacketPageError("");
  resetPreloadCounterState({
    preloadProcessedRef,
    preloadTotalRef,
    setPreloadProcessed,
    setPreloadTotal,
  });
  startCaptureParseRuntime({
    parseFinishedRef,
    parseErrorRef,
    preloadingRef,
    setIsPreloadingCapture,
  });
  setCaptureTransaction(createPendingCaptureTransactionStatus(opened.fileName, opened.filePath, hadActiveCapture));
  rememberRecentCapture(buildRecentCapture(opened, openedAt));
}
