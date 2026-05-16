import type { ToolRuntimeSnapshot } from "../core/types";

export function buildRuntimeProbeDiagnostics(snapshot?: ToolRuntimeSnapshot | null): string {
  if (!snapshot) return "";
  const mode = snapshot.probeMode === "fast" ? "快速" : snapshot.probeMode === "full" ? "完整" : "";
  const state = snapshot.probeState ? `状态 ${snapshot.probeState}` : "";
  const timings = snapshot.probeTimings
    ? Object.entries(snapshot.probeTimings)
        .map(([name, ms]) => `${name} ${ms}ms`)
        .join(" / ")
    : "";
  const errors = snapshot.probeErrors
    ? Object.entries(snapshot.probeErrors)
        .map(([name, error]) => `${name}: ${error}`)
        .join(" / ")
    : "";
  return [
    mode ? `探测模式：${mode}` : "",
    state,
    timings ? `组件耗时：${timings}` : "",
    errors ? `提示：${errors}` : "",
  ]
    .filter(Boolean)
    .join("；");
}
