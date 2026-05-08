import { type ReactNode } from "react";
import { Cog, LoaderCircle, type LucideIcon } from "lucide-react";
import { copyTextToClipboard, downloadText } from "../utils/browserFile";
import { EMPTY_SELECT_VALUE } from "./StreamDecoderWorkbenchUtils";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";

export function DecoderButton({
  icon: Icon,
  label,
  active,
  disabled,
  onClick,
}: {
  icon: LucideIcon;
  label: string;
  active: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || active}
      className="inline-flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-xs font-medium text-foreground shadow-sm transition-colors hover:bg-accent disabled:cursor-not-allowed disabled:opacity-60"
    >
      {active ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Icon className="h-3.5 w-3.5" />}
      {label}
    </button>
  );
}

export function ApplyModeButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors ${
        active
          ? "border-blue-300 bg-blue-50 text-blue-700"
          : "border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground"
      }`}
    >
      {label}
    </button>
  );
}

export function SettingsButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center rounded-lg border border-border bg-background p-2 text-muted-foreground shadow-sm transition-colors hover:bg-accent hover:text-foreground"
      title="解码设置"
    >
      <Cog className="h-3.5 w-3.5" />
    </button>
  );
}

export function DecoderSettingsSection({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold text-foreground">{title}</div>
        <button
          onClick={onClose}
          className="rounded border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          收起
        </button>
      </div>
      {children}
    </div>
  );
}

export function LabeledInput({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="rounded-md border border-border bg-background px-3 py-2 font-mono text-foreground outline-none focus:border-blue-500"
      />
    </label>
  );
}

export function LabeledSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<[string, string]>;
  onChange: (value: string) => void;
}) {
  const selectedValue = value === "" ? EMPTY_SELECT_VALUE : value;
  return (
    <div className="flex flex-col gap-1 text-xs text-muted-foreground">
      <span>{label}</span>
      <Select value={selectedValue} onValueChange={(next) => onChange(next === EMPTY_SELECT_VALUE ? "" : next)}>
        <SelectTrigger className="h-9 rounded-md border-border bg-background text-xs text-foreground focus:border-blue-500 focus:ring-blue-100">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map(([optionValue, optionLabel]) => (
            <SelectItem key={optionValue || EMPTY_SELECT_VALUE} value={optionValue || EMPTY_SELECT_VALUE}>
              {optionLabel}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export function LabeledToggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-xs text-foreground">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="accent-blue-600"
      />
      <span>{label}</span>
    </label>
  );
}

export function PayloadPane({
  title,
  content,
  error = false,
  loading = false,
  bytesHex,
  confidence,
  warnings,
  signals,
  attemptErrors,
  footer,
}: {
  title: string;
  content: string;
  error?: boolean;
  loading?: boolean;
  bytesHex?: string;
  confidence?: number;
  warnings?: string[];
  signals?: string[];
  attemptErrors?: string[];
  footer?: string;
}) {
  const downloadable = content.trim().length > 0 && content !== "点击上方解码器开始分析";

  function copyContent() {
    if (!downloadable) return;
    void copyTextToClipboard(content);
  }

  function exportContent() {
    if (!downloadable) return;
    downloadText(`payload-decode-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.txt`, content);
  }

  return (
    <div className="rounded-lg border border-border bg-background/90 p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-semibold text-foreground">{title}</div>
        <div className="flex items-center gap-2">
          {typeof confidence === "number" && confidence > 0 && (
            <span className="rounded border border-emerald-200 bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-700">
              置信度 {confidence}%
            </span>
          )}
          {loading && <span className="text-[11px] text-blue-600">解码中...</span>}
          {downloadable && (
            <>
              <button
                type="button"
                onClick={copyContent}
                className="rounded border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
              >
                复制
              </button>
              <button
                type="button"
                onClick={exportContent}
                className="rounded border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
              >
                导出
              </button>
            </>
          )}
        </div>
      </div>
      <pre
        className={`max-h-72 min-w-0 overflow-auto whitespace-pre-wrap break-all rounded-md border px-3 py-2 text-xs leading-5 ${error ? "border-rose-500/30 bg-rose-500/10 text-rose-700" : "border-border bg-card text-foreground"}`}
      >
        {content}
      </pre>
      {(warnings?.length ?? 0) > 0 && <TagList title="警告" items={warnings!} tone="amber" />}
      {(signals?.length ?? 0) > 0 && <TagList title="信号" items={signals!} tone="blue" />}
      {(attemptErrors?.length ?? 0) > 0 && <TagList title="自动检测失败阶段" items={attemptErrors!} tone="rose" />}
      {bytesHex && !error && (
        <div className="mt-2 rounded-md border border-border bg-card px-3 py-2">
          <div className="mb-1 text-[11px] font-semibold text-muted-foreground">Hex</div>
          <pre className="max-h-28 overflow-auto whitespace-pre-wrap break-all text-[11px] leading-5 text-muted-foreground">
            {bytesHex}
          </pre>
        </div>
      )}
      {footer && <div className="mt-2 text-[11px] text-blue-700">{footer}</div>}
    </div>
  );
}

function TagList({ title, items, tone }: { title: string; items: string[]; tone: "amber" | "blue" | "rose" }) {
  const toneClass =
    tone === "amber"
      ? "border-amber-200 bg-amber-50 text-amber-700"
      : tone === "rose"
        ? "border-rose-200 bg-rose-50 text-rose-700"
        : "border-blue-200 bg-blue-50 text-blue-700";
  return (
    <div className="mt-2 rounded-md border border-border bg-card px-3 py-2">
      <div className="mb-1 text-[11px] font-semibold text-muted-foreground">{title}</div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item) => (
          <span key={`${title}-${item}`} className={`rounded border px-2 py-0.5 text-[11px] ${toneClass}`}>
            {item}
          </span>
        ))}
      </div>
    </div>
  );
}
