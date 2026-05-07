import { useCallback, useState } from "react";
import type { ExtractedObject, ThreatHit } from "../../core/types";
import { bridge } from "../../integrations/wailsBridge";
import { isAbortLikeError } from "../../utils/asyncControl";
import type { CaptureTaskScope } from "../../utils/captureTaskScope";

export interface MediaAnalysisProgress {
  active: boolean;
  current: number;
  total: number;
  label: string;
  phase: "prepare" | "scan" | "organize" | "rebuild" | "complete" | "unknown";
  phaseLabel: string;
  percent: number;
  recent: string[];
}

export interface ThreatAnalysisProgress {
  active: boolean;
  current: number;
  total: number;
  label: string;
  phase: "prepare" | "packets" | "objects" | "streams" | "scan" | "complete" | "unknown";
  phaseLabel: string;
  percent: number;
  recent: string[];
}

export const EMPTY_MEDIA_ANALYSIS_PROGRESS: MediaAnalysisProgress = {
  active: false,
  current: 0,
  total: 0,
  label: "",
  phase: "unknown",
  phaseLabel: "",
  percent: 0,
  recent: [],
};

export const EMPTY_THREAT_ANALYSIS_PROGRESS: ThreatAnalysisProgress = {
  active: false,
  current: 0,
  total: 0,
  label: "",
  phase: "unknown",
  phaseLabel: "",
  percent: 0,
  recent: [],
};

export function phaseLabelForMediaProgress(phase: MediaAnalysisProgress["phase"]): string {
  switch (phase) {
    case "prepare": return "准备中";
    case "scan": return "扫描中";
    case "organize": return "整理中";
    case "rebuild": return "重建中";
    case "complete": return "已完成";
    default: return "处理中";
  }
}

export function phaseLabelForThreatProgress(phase: ThreatAnalysisProgress["phase"]): string {
  switch (phase) {
    case "prepare": return "准备中";
    case "packets": return "扫描数据包";
    case "objects": return "提取对象";
    case "streams": return "分析流";
    case "scan": return "规则扫描";
    case "complete": return "已完成";
    default: return "处理中";
  }
}

export function useAnalysisProgress(threatAnalysisSeqRef: React.MutableRefObject<number>) {
  const [threatHits, setThreatHits] = useState<ThreatHit[]>([]);
  const [isThreatAnalysisLoading, setIsThreatAnalysisLoading] = useState(false);
  const [threatAnalysisProgress, setThreatAnalysisProgress] = useState<ThreatAnalysisProgress>(EMPTY_THREAT_ANALYSIS_PROGRESS);
  const [extractedObjects, setExtractedObjects] = useState<ExtractedObject[]>([]);
  const [mediaAnalysisProgress, setMediaAnalysisProgress] = useState<MediaAnalysisProgress>(EMPTY_MEDIA_ANALYSIS_PROGRESS);

  const refreshAnalysisResult = useCallback(async (
    options: {
      capturePath?: string;
      quietSuccess?: boolean;
      backendConnected: boolean;
      activeCapturePath: string;
      captureTaskScope: CaptureTaskScope;
      setBackendStatus: (status: string) => void;
    },
  ) => {
    if (!options.backendConnected) return;
    const capturePath = options.capturePath ?? options.activeCapturePath;
    if (!capturePath) return;
    const seq = threatAnalysisSeqRef.current + 1;
    threatAnalysisSeqRef.current = seq;
    const task = options.captureTaskScope.beginTask("threat-analysis");
    setIsThreatAnalysisLoading(true);
    setThreatAnalysisProgress((prev) => ({
      ...EMPTY_THREAT_ANALYSIS_PROGRESS,
      active: true,
      current: 0,
      total: 5,
      label: "准备威胁分析",
      phase: "prepare",
      phaseLabel: phaseLabelForThreatProgress("prepare"),
      percent: prev.active && prev.percent > 0 ? prev.percent : 8,
      recent: ["准备威胁分析"],
    }));
    try {
      const objects = await bridge.listObjects(task.signal);
      if (!task.isCurrent() || threatAnalysisSeqRef.current !== seq || options.activeCapturePath !== capturePath) {
        return;
      }
      setExtractedObjects(objects);

      const hits = await bridge.listThreatHits(["flag{", "ctf{"], task.signal);
      if (!task.isCurrent() || threatAnalysisSeqRef.current !== seq || options.activeCapturePath !== capturePath) {
        return;
      }
      setThreatHits(hits);
      if (!options.quietSuccess) {
        options.setBackendStatus(`威胁分析已更新: ${hits.length} 条命中`);
      }
    } catch (error) {
      if (!task.isCurrent() || isAbortLikeError(error, task.signal)) {
        return;
      }
      if (threatAnalysisSeqRef.current === seq && options.activeCapturePath === capturePath) {
        options.setBackendStatus("威胁分析刷新失败");
        setThreatAnalysisProgress(EMPTY_THREAT_ANALYSIS_PROGRESS);
      }
    } finally {
      const isCurrent = task.isCurrent();
      task.finish();
      if (isCurrent && threatAnalysisSeqRef.current === seq && options.activeCapturePath === capturePath) {
        setIsThreatAnalysisLoading(false);
        setThreatAnalysisProgress((prev) => prev.phase === "complete" ? prev : EMPTY_THREAT_ANALYSIS_PROGRESS);
      }
    }
  }, []);

  return {
    threatHits,
    setThreatHits,
    isThreatAnalysisLoading,
    setIsThreatAnalysisLoading,
    threatAnalysisProgress,
    setThreatAnalysisProgress,
    extractedObjects,
    setExtractedObjects,
    mediaAnalysisProgress,
    setMediaAnalysisProgress,
    refreshAnalysisResult,
    EMPTY_MEDIA_ANALYSIS_PROGRESS,
    EMPTY_THREAT_ANALYSIS_PROGRESS,
  };
}
