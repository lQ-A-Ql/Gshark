import type { LucideIcon } from "lucide-react";

import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";

export function normalizeConfig(config?: ToolRuntimeConfig | null): ToolRuntimeConfig {
  return {
    tsharkPath: config?.tsharkPath ?? "",
    ffmpegPath: config?.ffmpegPath ?? "",
    pythonPath: config?.pythonPath ?? "",
    voskModelPath: config?.voskModelPath ?? "",
    yaraEnabled: config?.yaraEnabled ?? true,
    yaraBin: config?.yaraBin ?? "",
    yaraRules: config?.yaraRules ?? "",
    yaraTimeoutMs: config?.yaraTimeoutMs && config.yaraTimeoutMs > 0 ? config.yaraTimeoutMs : 25000,
  };
}

export function statusTone(available: boolean, enabled = true) {
  if (!enabled) {
    return "border-slate-200 bg-slate-50 text-slate-500";
  }
  return available ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-rose-200 bg-rose-50 text-rose-700";
}

export function Field({
  label,
  hint,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  hint?: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-xs font-medium text-slate-700">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-9 rounded-lg border border-slate-200 bg-white px-3 text-xs text-slate-900 outline-none transition focus:border-blue-400"
      />
      {hint ? <span className="text-[11px] leading-5 text-slate-500">{hint}</span> : null}
    </label>
  );
}

export function StatusLine({
  label,
  available,
  message,
  path,
  enabled = true,
  preferMessageWhenUnavailable = false,
}: {
  label: string;
  available: boolean;
  message: string;
  path?: string;
  enabled?: boolean;
  preferMessageWhenUnavailable?: boolean;
}) {
  const resolvedText = !enabled
    ? message || "当前组件已关闭"
    : !available && preferMessageWhenUnavailable
      ? message || "等待检测"
      : path?.trim()
        ? path
        : message || "等待检测";
  return (
    <div className={`rounded-xl border px-3 py-2 ${statusTone(available, enabled)}`}>
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-semibold">{label}</span>
        <span className="text-[11px]">{!enabled ? "已关闭" : available ? "已就绪" : "未就绪"}</span>
      </div>
      <div className="mt-1 break-all text-[11px] leading-5">{resolvedText}</div>
    </div>
  );
}

export function MiniStatus({
  label,
  available,
  enabled = true,
}: {
  label: string;
  available: boolean;
  enabled?: boolean;
}) {
  const tone = statusTone(available, enabled);
  return (
    <div className={`rounded-2xl border px-3 py-2 ${tone}`}>
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em]">{label}</div>
      <div className="mt-1 text-sm font-semibold">{!enabled ? "已关闭" : available ? "就绪" : "缺失"}</div>
    </div>
  );
}

export function RuntimeDependencyCard({
  label,
  value,
  available,
  Icon,
}: {
  label: string;
  value: string;
  available: boolean;
  Icon: LucideIcon;
}) {
  return (
    <div className={`rounded-xl border px-3 py-2 ${statusTone(available)}`}>
      <div className="flex items-center gap-1 text-xs font-semibold">
        <Icon className="h-3.5 w-3.5" /> {label}
      </div>
      <div className="mt-1 break-all text-[11px] leading-5">{value}</div>
    </div>
  );
}

export function buildSpeechIssues(snapshot?: ToolRuntimeSnapshot | null) {
  const speech = snapshot?.speech;
  if (!speech) {
    return [];
  }
  const issues: string[] = [];
  if (!speech.pythonAvailable) {
    issues.push("Python 不可用");
  }
  if (!speech.voskAvailable) {
    issues.push("vosk 模块缺失");
  }
  if (!speech.modelAvailable) {
    issues.push("Vosk 模型目录缺失");
  }
  if (!speech.ffmpegAvailable) {
    issues.push("ffmpeg 不可用");
  }
  return issues;
}
