import { RefreshCw, Save, Sparkles } from "lucide-react";

import type { ToolRuntimeSnapshot } from "../core/types";
import {
  toolRuntimeProbeTransportText,
  type ToolRuntimeProbeState,
  type ToolRuntimeProbeTransport,
} from "../state/toolRuntimeProbeState";
import { buildRuntimeProbeDiagnostics } from "./runtimeProbeDiagnosticsText";

export function RuntimeSettingsActions({
  busy,
  loading,
  backendConnected,
  dirty,
  onRefresh,
  onSave,
}: {
  busy: boolean;
  loading: boolean;
  backendConnected: boolean;
  dirty: boolean;
  onRefresh: () => void;
  onSave: () => void;
}) {
  return (
    <div className="gshark-tile-toolbar flex items-center gap-2 border-x-0 border-t-0 px-5 py-3">
      <button
        onClick={onRefresh}
        disabled={busy || loading || !backendConnected}
        className="gshark-control inline-flex h-10 items-center gap-2 px-3.5 text-xs font-medium text-slate-700 transition disabled:cursor-not-allowed disabled:opacity-60"
      >
        <RefreshCw className={`h-3.5 w-3.5 ${busy || loading ? "animate-spin" : ""}`} />
        重新探测工具
      </button>
      <button
        onClick={onSave}
        disabled={busy || loading || !dirty}
        className="gshark-control-primary inline-flex h-10 items-center gap-2 px-3.5 text-xs font-medium transition disabled:cursor-not-allowed disabled:opacity-60"
      >
        <Save className="h-3.5 w-3.5" />
        保存并应用
      </button>
    </div>
  );
}

export function RuntimeSettingsFooter({
  notice,
  backendConnected,
  probeState,
  probeTransport,
  probeError,
  probeTransportError,
  snapshot,
}: {
  notice: string;
  backendConnected: boolean;
  probeState: ToolRuntimeProbeState;
  probeTransport: ToolRuntimeProbeTransport;
  probeError: string;
  probeTransportError?: string;
  snapshot?: ToolRuntimeSnapshot | null;
}) {
  const diagnosticsText = buildRuntimeProbeDiagnostics(snapshot);
  const probeText =
    probeState === "failed"
      ? `最近一次探测失败（${toolRuntimeProbeTransportText(probeTransport)}）：${probeError || "未知错误"}`
      : probeState === "probing" || probeState === "probing_fast"
        ? `正在通过 ${toolRuntimeProbeTransportText(probeTransport)} 快速探测运行时组件。`
        : probeState === "probing_full"
          ? `快速状态已可用，正在后台执行完整能力探测。${diagnosticsText ? ` ${diagnosticsText}` : ""}`
          : probeState === "timeout_background"
            ? `完整能力探测仍在后台进行：${probeError || "慢探测尚未返回"}`
            : probeTransportError
              ? `最近一次探测已通过 ${toolRuntimeProbeTransportText(probeTransport)} 完成；备用链路原因：${probeTransportError}`
              : diagnosticsText;
  return (
    <div className="gshark-tile-toolbar border-x-0 border-b-0 px-5 py-4">
      <div className="gshark-soft-fill flex items-start gap-2 px-3 py-3 text-[11px] leading-5 text-slate-500">
        <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
        <div>
          {notice ||
            probeText ||
            (backendConnected
              ? "路径修改后会立即应用到当前后端进程。清空并保存 FFmpeg、Python 或 Vosk 字段会移除本进程对应的 GSHARK_* 显式配置；刷新超时或后端不可达时会在这里显示原因。"
              : "后端暂时未连接，不过可以先填写路径，待后端连上后会自动重新应用。")}
        </div>
      </div>
    </div>
  );
}
