import type { MediaAnalysisProgress, ThreatAnalysisProgress } from "./hooks/useAnalysisProgress";
import { phaseLabelForMediaProgress, phaseLabelForThreatProgress } from "./hooks/useAnalysisProgress";
import {
  classifyMediaProgressPhase,
  classifyThreatProgressPhase,
  computeMediaProgressPercent,
  computeThreatProgressPercent,
} from "./progressHelpers";
import { parseProgressStatus, pushRecentLabel } from "./progressStatus";

type MutableRef<T> = { current: T };

export interface UpdateProgressFromStatusOptions {
  message: string;
  preloadProcessedRef: MutableRef<number>;
  preloadTotalRef: MutableRef<number>;
  setPreloadProcessed: (value: number) => void;
  setPreloadTotal: (value: number) => void;
  setTotalPackets: (value: number) => void;
  setMediaAnalysisProgress: (updater: (prev: MediaAnalysisProgress) => MediaAnalysisProgress) => void;
  setThreatAnalysisProgress: (updater: (prev: ThreatAnalysisProgress) => ThreatAnalysisProgress) => void;
}

export function updateProgressFromStatusState(options: UpdateProgressFromStatusOptions): boolean {
  const progress = parseProgressStatus(options.message);
  if (!progress.consumed) return false;
  if (progress.kind === "malformed") return true;
  if (progress.kind === "media") {
    const { current, total, label } = progress;
    const progressPhase = classifyMediaProgressPhase(label);
    const percent = computeMediaProgressPercent(progressPhase, current, total);
    options.setMediaAnalysisProgress((prev) => {
      const nextRecent = label !== prev.label ? pushRecentLabel(prev.recent, label, 4) : prev.recent;
      return {
        active: progressPhase !== "complete" && (total <= 0 || current < total),
        current,
        total,
        label,
        phase: progressPhase,
        phaseLabel: phaseLabelForMediaProgress(progressPhase),
        percent,
        recent: nextRecent,
      };
    });
    return true;
  }
  if (progress.kind === "threat") {
    const { current, total, label } = progress;
    const progressPhase = classifyThreatProgressPhase(label);
    const percent = computeThreatProgressPercent(progressPhase, current, total);
    options.setThreatAnalysisProgress((prev) => {
      const nextRecent = label !== prev.label ? pushRecentLabel(prev.recent, label, 5) : prev.recent;
      return {
        active: progressPhase !== "complete" && (total <= 0 || current < total),
        current,
        total,
        label,
        phase: progressPhase,
        phaseLabel: phaseLabelForThreatProgress(progressPhase),
        percent,
        recent: nextRecent,
      };
    });
    return true;
  }

  const { phase, processed, total } = progress;
  if (total > 0) {
    options.setPreloadTotal(total);
    options.preloadTotalRef.current = total;
    options.setTotalPackets(total);
  }
  if (phase === "counting") {
    options.setPreloadProcessed(0);
    options.preloadProcessedRef.current = 0;
    return true;
  }
  const safeProcessed = Math.max(0, processed);
  options.setPreloadProcessed(safeProcessed);
  options.preloadProcessedRef.current = safeProcessed;
  return true;
}
