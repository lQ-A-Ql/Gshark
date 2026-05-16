import type { ToolRuntimeConfig } from "../core/types";

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

export function statusTone(available?: boolean, enabled = true) {
  if (!enabled) {
    return "border-slate-200 bg-slate-50 text-slate-500";
  }
  if (available === undefined) {
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
  known = true,
  degraded = false,
  unknownStateText = "未检测",
  preferMessageWhenUnavailable = false,
}: {
  label: string;
  available?: boolean;
  message: string;
  path?: string;
  enabled?: boolean;
  known?: boolean;
  degraded?: boolean;
  unknownStateText?: string;
  preferMessageWhenUnavailable?: boolean;
}) {
  const ready = Boolean(available);
  const resolvedText = !known
    ? message || "等待检测"
    : !enabled
      ? message || "当前组件已关闭"
      : !ready && preferMessageWhenUnavailable
        ? message || "等待检测"
        : path?.trim()
          ? path
          : message || "等待检测";
  const stateText = !known
    ? unknownStateText
    : !enabled
      ? "已关闭"
      : degraded
        ? "部分降级"
        : ready
          ? "已就绪"
          : "未就绪";
  return (
    <div
      className={`rounded-xl border px-3 py-2 ${degraded ? "border-amber-200 bg-amber-50 text-amber-700" : statusTone(ready, enabled && known)}`}
    >
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-semibold">{label}</span>
        <span className="text-[11px]">{stateText}</span>
      </div>
      <div className="mt-1 break-all text-[11px] leading-5">{resolvedText}</div>
    </div>
  );
}

export function MiniStatus({
  label,
  available,
  enabled = true,
  known = true,
  degraded = false,
  unknownLabel = "未检测",
}: {
  label: string;
  available?: boolean;
  enabled?: boolean;
  known?: boolean;
  degraded?: boolean;
  unknownLabel?: string;
}) {
  const ready = Boolean(available);
  const tone = degraded ? "border-amber-200 bg-amber-50 text-amber-700" : statusTone(ready, enabled && known);
  const text = !known ? unknownLabel : !enabled ? "已关闭" : degraded ? "降级" : ready ? "就绪" : "缺失";
  return (
    <div className={`rounded-2xl border px-3 py-2 ${tone}`}>
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em]">{label}</div>
      <div className="mt-1 text-sm font-semibold">{text}</div>
    </div>
  );
}
