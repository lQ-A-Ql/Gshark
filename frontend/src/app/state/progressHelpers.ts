import type { MediaAnalysisProgress, ThreatAnalysisProgress } from "./hooks/useAnalysisProgress";

export function classifyMediaProgressPhase(label: string): MediaAnalysisProgress["phase"] {
  const normalized = label.trim();
  if (!normalized) return "unknown";
  if (normalized.includes("准备")) return "prepare";
  if (normalized.includes("扫描")) return "scan";
  if (normalized.includes("整理")) return "organize";
  if (normalized.includes("重建")) return "rebuild";
  if (normalized.includes("完成")) return "complete";
  return "unknown";
}

export function computeMediaProgressPercent(
  phase: MediaAnalysisProgress["phase"],
  current: number,
  total: number,
): number {
  const safeTotal = total > 0 ? total : 0;
  const local = safeTotal > 0 ? Math.max(0, Math.min(1, current / Math.max(safeTotal, 1))) : 0;
  switch (phase) {
    case "prepare":
      return Math.max(1, local * 5);
    case "scan":
      return 5 + local * 67;
    case "organize":
      return 72 + local * 10;
    case "rebuild":
      return 82 + local * 18;
    case "complete":
      return 100;
    default:
      return safeTotal > 0 ? local * 100 : 0;
  }
}

export function classifyThreatProgressPhase(label: string): ThreatAnalysisProgress["phase"] {
  const normalized = label.trim();
  if (!normalized) return "unknown";
  if (normalized.includes("准备")) return "prepare";
  if (normalized.includes("基础特征") || normalized.includes("数据包")) return "packets";
  if (normalized.includes("对象")) return "objects";
  if (normalized.includes("重组流") || normalized.includes("扫描目标")) return "streams";
  if (normalized.includes("YARA") || normalized.includes("扫描")) return "scan";
  if (normalized.includes("完成")) return "complete";
  return "unknown";
}

export function computeThreatProgressPercent(
  phase: ThreatAnalysisProgress["phase"],
  current: number,
  total: number,
): number {
  if (total > 0) {
    return Math.max(0, Math.min(100, Math.round((current / total) * 100)));
  }
  switch (phase) {
    case "prepare":
      return 8;
    case "packets":
      return 24;
    case "objects":
      return 42;
    case "streams":
      return 64;
    case "scan":
      return 84;
    case "complete":
      return 100;
    default:
      return 12;
  }
}
