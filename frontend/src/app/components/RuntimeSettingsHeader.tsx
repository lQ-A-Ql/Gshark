import { X } from "lucide-react";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import {
  toolRuntimeProbeStateText,
  toolRuntimeProbeTransportText,
  type ToolRuntimeProbeState,
  type ToolRuntimeProbeTransport,
} from "../state/toolRuntimeProbeState";
import { MiniStatus } from "./RuntimeSettingsSidebarParts";
import { isTSharkSnapshotDegraded } from "./runtimeTSharkStatus";

type RuntimeSettingsHeaderProps = {
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  probeState: ToolRuntimeProbeState;
  probeTransport: ToolRuntimeProbeTransport;
  probeError: string;
  onClose: () => void;
};

export function RuntimeSettingsHeader({
  form,
  snapshot,
  probeState,
  probeTransport,
  probeError,
  onClose,
}: RuntimeSettingsHeaderProps) {
  const known = Boolean(snapshot);
  const unknownLabel = probeState === "failed" ? "失败" : probeState === "probing" ? "探测中" : "等待";
  return (
    <div className="border-b border-slate-200 bg-[linear-gradient(135deg,rgba(239,246,255,0.92),rgba(255,255,255,0.98))] px-5 py-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-blue-600">Runtime Settings</div>
          <div className="mt-2 text-[22px] font-semibold leading-none text-slate-900">运行时组件设置</div>
          <p className="mt-2 max-w-md text-xs leading-5 text-slate-600">
            输入框只代表显式配置路径；下方状态卡显示当前探测路径。保存后会立即重新检测。
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white/90 text-slate-500 transition hover:border-slate-300 hover:text-slate-800"
          title="收起设置侧栏"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2">
        <MiniStatus
          label="TShark"
          available={snapshot?.tshark.available}
          known={known}
          degraded={isTSharkSnapshotDegraded(snapshot)}
          unknownLabel={unknownLabel}
        />
        <MiniStatus label="FFmpeg" available={snapshot?.ffmpeg.available} known={known} unknownLabel={unknownLabel} />
        <MiniStatus label="Speech" available={snapshot?.speech.available} known={known} unknownLabel={unknownLabel} />
        <MiniStatus
          label="YARA"
          available={snapshot?.yara.available}
          enabled={snapshot?.yara.enabled ?? form.yaraEnabled}
          known={known}
          unknownLabel={unknownLabel}
        />
      </div>
      {!known || probeState === "failed" ? (
        <div
          className={`mt-3 rounded-xl border px-3 py-2 text-[11px] leading-5 ${
            probeState === "failed"
              ? "border-rose-200 bg-rose-50 text-rose-700"
              : "border-slate-200 bg-white/80 text-slate-600"
          }`}
        >
          {toolRuntimeProbeStateText(probeState)} · {toolRuntimeProbeTransportText(probeTransport)}
          {probeError ? `：${probeError}` : "。后端连接后会自动探测，也可以点击重新探测工具。"}
        </div>
      ) : null}
    </div>
  );
}
