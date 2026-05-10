import { useCallback, type Dispatch, type MutableRefObject, type SetStateAction } from "react";
import { updateProgressFromStatusState } from "../progressStatusWorkflow";
import type { MediaAnalysisProgress, ThreatAnalysisProgress } from "./useAnalysisProgress";

interface UseProgressStatusUpdaterOptions {
  readonly preloadProcessedRef: MutableRefObject<number>;
  readonly preloadTotalRef: MutableRefObject<number>;
  readonly setPreloadProcessed: Dispatch<SetStateAction<number>>;
  readonly setPreloadTotal: Dispatch<SetStateAction<number>>;
  readonly setTotalPackets: Dispatch<SetStateAction<number>>;
  readonly setMediaAnalysisProgress: Dispatch<SetStateAction<MediaAnalysisProgress>>;
  readonly setThreatAnalysisProgress: Dispatch<SetStateAction<ThreatAnalysisProgress>>;
}

export function useProgressStatusUpdater(options: UseProgressStatusUpdaterOptions) {
  return useCallback(
    (message: string): boolean =>
      updateProgressFromStatusState({
        message,
        ...options,
      }),
    [options],
  );
}
