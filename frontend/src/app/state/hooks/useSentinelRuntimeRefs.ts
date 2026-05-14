import { useRef, type Dispatch, type SetStateAction } from "react";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";

export function useSentinelRuntimeRefs() {
  return {
    activeCapturePathRef: useRef(""),
    captureSeqRef: useRef(0),
    captureTaskScopeRef: useRef(createCaptureTaskScope()),
    filterSeqRef: useRef(0),
    parseErrorRef: useRef(""),
    parseFinishedRef: useRef(false),
    preloadingRef: useRef(false),
    refreshAnalysisResultRef: useRef<(options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>>(
      async () => {},
    ),
    scheduleLoadMoreRef: useRef<() => void>(() => undefined),
    setSelectedPacketIdRef: useRef<Dispatch<SetStateAction<number | null>>>(() => undefined),
    threatAnalysisSeqRef: useRef(0),
    updateProgressFromStatusRef: useRef<(message: string) => boolean>(() => false),
  };
}
