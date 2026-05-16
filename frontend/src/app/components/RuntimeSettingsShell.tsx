import { RefreshCw, Save, Sparkles } from "lucide-react";

import {
  toolRuntimeProbeTransportText,
  type ToolRuntimeProbeState,
  type ToolRuntimeProbeTransport,
} from "../state/toolRuntimeProbeState";

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
    <div className="flex items-center gap-2 border-b border-slate-200 bg-white/90 px-5 py-3">
      <button
        onClick={onRefresh}
        disabled={busy || loading || !backendConnected}
        className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <RefreshCw className={`h-3.5 w-3.5 ${busy || loading ? "animate-spin" : ""}`} />
        重新探测工具
      </button>
      <button
        onClick={onSave}
        disabled={busy || loading || !dirty}
        className="inline-flex h-10 items-center gap-2 rounded-xl border border-blue-200 bg-blue-600 px-3.5 text-xs font-medium text-white transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-60"
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
}: {
  notice: string;
  backendConnected: boolean;
  probeState: ToolRuntimeProbeState;
  probeTransport: ToolRuntimeProbeTransport;
  probeError: string;
}) {
  const probeText =
    probeState === "failed"
      ? `最近一次探测失败（${toolRuntimeProbeTransportText(probeTransport)}）：${probeError || "未知错误"}`
      : probeState === "probing"
        ? `正在通过 ${toolRuntimeProbeTransportText(probeTransport)} 探测运行时组件。`
        : "";
  return (
    <div className="border-t border-slate-200 bg-white/90 px-5 py-4">
      <div className="flex items-start gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 text-[11px] leading-5 text-slate-500">
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
