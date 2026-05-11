import type { ThreatHuntingProgressView } from "./ThreatHuntingPanels";

export function parseThreatPrefixes(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function buildThreatHuntingProgressView({
  huntBusy,
  isThreatAnalysisLoading,
  progress,
}: {
  huntBusy: boolean;
  isThreatAnalysisLoading: boolean;
  progress: {
    active: boolean;
    label: string;
    percent: number;
    phaseLabel: string;
    current: number;
    total: number;
  };
}): ThreatHuntingProgressView | null {
  if (progress.active) {
    return {
      title: huntBusy ? "正在执行狩猎" : "后台威胁分析进行中",
      detail: progress.label || "正在整理对象、重组流并执行 YARA 扫描。",
      value: Math.max(4, progress.percent || 4),
      phaseLabel: progress.phaseLabel || "处理中",
      current: progress.current,
      total: progress.total,
    };
  }
  if (huntBusy || isThreatAnalysisLoading) {
    return {
      title: huntBusy ? "正在执行狩猎" : "后台威胁分析进行中",
      detail: "正在准备威胁分析任务...",
      value: 12,
      phaseLabel: "准备",
      current: 0,
      total: 5,
    };
  }
  return null;
}

export function routeForPreparedStream(protocol?: string) {
  if (protocol === "HTTP") return "/http-stream";
  if (protocol === "UDP") return "/udp-stream";
  return "/tcp-stream";
}
