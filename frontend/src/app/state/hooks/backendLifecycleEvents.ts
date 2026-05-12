import type { Dispatch, MutableRefObject, SetStateAction } from "react";
import type { Packet } from "../../core/types";
import type { EventHandlers } from "../../integrations/bridgeTypes";
import {
  EMPTY_MEDIA_ANALYSIS_PROGRESS,
  EMPTY_THREAT_ANALYSIS_PROGRESS,
  type MediaAnalysisProgress,
  type ThreatAnalysisProgress,
} from "./useAnalysisProgress";
import {
  isProgressStatusMessage,
  shouldIgnoreCaptureErrorWithoutActiveCapture,
  shouldIgnoreCaptureStatusWithoutActiveCapture,
  shouldMarkParseErrorFromStatus,
  shouldMarkParseFinishedFromStatus,
  shouldResetMediaAnalysisFromError,
  shouldResetMediaAnalysisFromStatus,
  shouldResetThreatAnalysisFromError,
  shouldResetThreatAnalysisFromStatus,
} from "../backendStatusMessage";
import { markCaptureParseFinished } from "../captureParseRuntimeState";
import { preserveSelectedPacketId } from "../selectedPacketState";

export interface BackendLifecycleEventOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly parseFinishedRef: MutableRefObject<boolean>;
  readonly parseErrorRef: MutableRefObject<string>;
  readonly preloadingRef: MutableRefObject<boolean>;
  readonly refreshTimerRef: MutableRefObject<number | null>;
  readonly scheduleLoadMoreRef: MutableRefObject<() => void>;
  readonly refreshAnalysisResultRef: MutableRefObject<(options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>>;
  readonly updateProgressFromStatusRef: MutableRefObject<(message: string) => boolean>;
  readonly wakeCaptureWaiters: () => void;
  readonly setSelectedPacketId: Dispatch<SetStateAction<number | null>>;
  readonly setMediaAnalysisProgress: Dispatch<SetStateAction<MediaAnalysisProgress>>;
  readonly setThreatAnalysisProgress: Dispatch<SetStateAction<ThreatAnalysisProgress>>;
  readonly setIsThreatAnalysisLoading: Dispatch<SetStateAction<boolean>>;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
}

export function createBackendLifecycleEventHandlers({
  activeCapturePathRef,
  parseFinishedRef,
  parseErrorRef,
  preloadingRef,
  refreshTimerRef,
  scheduleLoadMoreRef,
  refreshAnalysisResultRef,
  updateProgressFromStatusRef,
  wakeCaptureWaiters,
  setSelectedPacketId,
  setMediaAnalysisProgress,
  setThreatAnalysisProgress,
  setIsThreatAnalysisLoading,
  setBackendStatus,
}: BackendLifecycleEventOptions): EventHandlers {
  return {
    packet: (packet: Packet) => {
      setSelectedPacketId((prev) => preserveSelectedPacketId(prev, packet.id));
      if (preloadingRef.current) {
        return;
      }
      scheduleLoadMoreRef.current();

      if (refreshTimerRef.current != null) {
        window.clearTimeout(refreshTimerRef.current);
      }
      refreshTimerRef.current = window.setTimeout(() => {
        void refreshAnalysisResultRef.current();
      }, 500);
    },
    status: (message) => {
      const msg = message || "后端运行中";
      if (shouldIgnoreCaptureStatusWithoutActiveCapture(msg, Boolean(activeCapturePathRef.current))) {
        return;
      }
      if (isProgressStatusMessage(msg)) {
        updateProgressFromStatusRef.current(msg);
        wakeCaptureWaiters();
        return;
      }
      if (shouldMarkParseFinishedFromStatus(msg)) {
        markCaptureParseFinished({
          parseFinishedRef,
          parseErrorRef,
          errorMessage: shouldMarkParseErrorFromStatus(msg) ? msg : undefined,
        });
      }
      if (shouldResetMediaAnalysisFromStatus(msg)) {
        setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
      }
      if (shouldResetThreatAnalysisFromStatus(msg)) {
        setThreatAnalysisProgress((prev) => (prev.phase === "complete" ? prev : EMPTY_THREAT_ANALYSIS_PROGRESS));
      }
      wakeCaptureWaiters();
      setBackendStatus(msg);
    },
    error: (message) => {
      const next = message || "后端事件异常";
      if (shouldIgnoreCaptureErrorWithoutActiveCapture(next, Boolean(activeCapturePathRef.current))) {
        return;
      }
      if (preloadingRef.current) {
        markCaptureParseFinished({
          parseFinishedRef,
          parseErrorRef,
          errorMessage: next,
        });
      }
      if (shouldResetMediaAnalysisFromError(next)) {
        setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
      }
      if (shouldResetThreatAnalysisFromError(next)) {
        setThreatAnalysisProgress(EMPTY_THREAT_ANALYSIS_PROGRESS);
        setIsThreatAnalysisLoading(false);
      }
      wakeCaptureWaiters();
      setBackendStatus(next);
    },
  };
}
