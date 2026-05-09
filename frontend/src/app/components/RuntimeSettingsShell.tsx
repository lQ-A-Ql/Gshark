import { RefreshCw, Save, Sparkles, X } from "lucide-react";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";
import { MiniStatus } from "./RuntimeSettingsSidebarParts";

export function RuntimeSettingsHeader({
  form,
  snapshot,
  onClose,
}: {
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  onClose: () => void;
}) {
  return (
    <div className="border-b border-slate-200 bg-[linear-gradient(135deg,rgba(239,246,255,0.92),rgba(255,255,255,0.98))] px-5 py-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-blue-600">Runtime Settings</div>
          <div className="mt-2 text-[22px] font-semibold leading-none text-slate-900">运行时组件设置</div>
          <p className="mt-2 max-w-md text-xs leading-5 text-slate-600">
            这里统一管理抓包、YARA、媒体播放和离线语音转写依赖的本地组件路径。
            保存之后会立即重新检测，方便直接确认当前环境是否已经接好。
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
        <MiniStatus label="TShark" available={snapshot?.tshark.available ?? false} />
        <MiniStatus label="FFmpeg" available={snapshot?.ffmpeg.available ?? false} />
        <MiniStatus label="Speech" available={snapshot?.speech.available ?? false} />
        <MiniStatus
          label="YARA"
          available={snapshot?.yara.available ?? false}
          enabled={snapshot?.yara.enabled ?? form.yaraEnabled}
        />
      </div>
    </div>
  );
}

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
        刷新状态
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

export function RuntimeSettingsFooter({ notice, backendConnected }: { notice: string; backendConnected: boolean }) {
  return (
    <div className="border-t border-slate-200 bg-white/90 px-5 py-4">
      <div className="flex items-start gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 text-[11px] leading-5 text-slate-500">
        <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" />
        <div>
          {notice ||
            (backendConnected
              ? "路径修改后会立即应用到当前桌面端运行时，重启后也会自动重新加载这些设置。"
              : "后端暂时未连接，不过可以先填写路径，待后端连上后会自动重新应用。")}
        </div>
      </div>
    </div>
  );
}
