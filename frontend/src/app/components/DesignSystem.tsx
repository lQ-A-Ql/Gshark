import type { ReactNode } from "react";
import { ArrowLeft, ChevronLeft, ChevronRight, Copy, Download, Search, X } from "lucide-react";
import { cn } from "./ui/utils";

type Tone = "slate" | "blue" | "cyan" | "emerald" | "amber" | "rose" | "indigo" | "violet";
type SurfaceVariant = "page" | "section" | "flat" | "subtle";

const toneClasses: Record<Tone, { icon: string; hint: string }> = {
  slate: { icon: "border-slate-200 bg-slate-50 text-slate-600", hint: "border-slate-200 bg-slate-50 text-slate-600" },
  blue: { icon: "border-blue-100 bg-blue-50 text-blue-600", hint: "border-blue-100 bg-blue-50 text-blue-700" },
  cyan: { icon: "border-cyan-100 bg-cyan-50 text-cyan-600", hint: "border-cyan-100 bg-cyan-50 text-cyan-700" },
  emerald: { icon: "border-emerald-100 bg-emerald-50 text-emerald-600", hint: "border-emerald-100 bg-emerald-50 text-emerald-700" },
  amber: { icon: "border-amber-100 bg-amber-50 text-amber-600", hint: "border-amber-100 bg-amber-50 text-amber-700" },
  rose: { icon: "border-rose-100 bg-rose-50 text-rose-600", hint: "border-rose-100 bg-rose-50 text-rose-700" },
  indigo: { icon: "border-indigo-100 bg-indigo-50 text-indigo-600", hint: "border-indigo-100 bg-indigo-50 text-indigo-700" },
  violet: { icon: "border-violet-100 bg-violet-50 text-violet-600", hint: "border-violet-100 bg-violet-50 text-violet-700" },
};

const surfaceClasses: Record<SurfaceVariant, string> = {
  page: "rounded-[28px] border border-slate-200/80 bg-white/92 shadow-[0_24px_80px_-54px_rgba(15,23,42,0.42)]",
  section: "rounded-[24px] border border-slate-200/80 bg-white/90 shadow-[0_18px_58px_-48px_rgba(15,23,42,0.5)]",
  flat: "rounded-2xl border border-slate-100 bg-slate-50/60 shadow-none",
  subtle: "rounded-2xl border border-slate-100 bg-white/80 shadow-none",
};

export function SurfacePanel({
  title,
  description,
  icon,
  actions,
  children,
  className,
  bodyClassName,
  headerClassName,
  variant = "page",
}: {
  title?: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  headerClassName?: string;
  variant?: SurfaceVariant;
}) {
  const hasHeader = title || description || icon || actions;
  return (
    <section className={cn("min-w-0 overflow-hidden", surfaceClasses[variant], className)}>
      {hasHeader ? (
        <div className={cn("border-b border-slate-100 px-5 py-4", variant === "flat" && "bg-transparent", headerClassName)}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              {title || icon ? (
                <div className="flex min-w-0 items-center gap-2 text-sm font-semibold text-slate-900">
                  {icon ? <span className="shrink-0">{icon}</span> : null}
                  <span className="truncate">{title}</span>
                </div>
              ) : null}
              {description ? <div className="mt-1 text-xs leading-5 text-slate-500">{description}</div> : null}
            </div>
            {actions ? <div className="shrink-0">{actions}</div> : null}
          </div>
        </div>
      ) : null}
      <div className={cn(variant === "flat" ? "p-4" : "p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

export function MetricCard({
  label,
  value,
  hint,
  icon,
  tone = "slate",
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <div className={cn("rounded-[24px] border border-white/80 bg-white/88 p-4 shadow-[0_22px_64px_-52px_rgba(15,23,42,0.5)]", className)}>
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-400">{label}</div>
        {icon ? <div className={cn("rounded-2xl border p-2", toneClasses[tone].icon)}>{icon}</div> : null}
      </div>
      <div className="mt-3 text-2xl font-semibold tracking-tight text-slate-950">{value}</div>
      {hint ? <div className="mt-1 text-xs leading-5 text-slate-500">{hint}</div> : null}
    </div>
  );
}

export function StatusHint({
  children,
  tone = "slate",
  className,
}: {
  children: ReactNode;
  tone?: Tone;
  className?: string;
}) {
  return (
    <div className={cn("rounded-2xl border px-4 py-3 text-xs leading-5", toneClasses[tone].hint, className)}>
      {children}
    </div>
  );
}

export function EmptyState({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-center text-xs leading-6 text-slate-500", className)}>
      {children}
    </div>
  );
}

export function CollapsibleContent({
  open,
  children,
  className,
}: {
  open: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      aria-hidden={!open}
      className={cn(
        "grid transition-[grid-template-rows,opacity,visibility] duration-300 ease-[cubic-bezier(0.22,1,0.36,1)]",
        open ? "visible grid-rows-[1fr] opacity-100" : "pointer-events-none invisible grid-rows-[0fr] opacity-0",
        className,
      )}
    >
      <div className="min-h-0 overflow-hidden">{children}</div>
    </div>
  );
}

export function WorkbenchTitleBar({
  title,
  subtitle,
  icon,
  onBack,
  meta,
  actions,
  className,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  onBack?: () => void;
  meta?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-border bg-white px-4 py-2.5 text-foreground shadow-sm", className)}>
      <div className="flex min-w-0 items-center gap-3">
        {onBack ? (
          <button onClick={onBack} className="rounded-md border border-border bg-background p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground" title="返回上一页">
            <ArrowLeft className="h-4 w-4" />
          </button>
        ) : null}
        {onBack ? <div className="h-5 w-px bg-border" /> : null}
        {icon ? <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-slate-600">{icon}</div> : null}
        <div className="min-w-0">
          <h1 className="truncate text-sm font-semibold text-foreground">{title}</h1>
          {subtitle ? <div className="mt-0.5 min-w-0 text-[11px] leading-4 text-muted-foreground">{subtitle}</div> : null}
        </div>
      </div>
      <div className="flex min-w-0 flex-1 flex-wrap items-center justify-end gap-2">
        {meta}
        {actions}
      </div>
    </div>
  );
}

export function WorkbenchChip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex min-h-7 items-center rounded-md border border-border bg-background px-2 py-1 text-[11px] leading-4 text-muted-foreground", className)}>
      {children}
    </span>
  );
}

export function StreamNavigator({
  protocolLabel,
  ordinalLabel,
  streamId,
  streamTotal,
  streamInput,
  onStreamInputChange,
  onSubmitStream,
  onPrev,
  onNext,
  hasPrev,
  hasNext,
  disabled,
  className,
}: {
  protocolLabel: string;
  ordinalLabel: string;
  streamId: number;
  streamTotal: number;
  streamInput: string;
  onStreamInputChange: (value: string) => void;
  onSubmitStream: () => void;
  onPrev: () => void;
  onNext: () => void;
  hasPrev: boolean;
  hasNext: boolean;
  disabled?: boolean;
  className?: string;
}) {
  const title = `${protocolLabel} 流总数: ${streamTotal}`;
  return (
    <div className={cn("flex flex-wrap items-center gap-2 rounded-md border border-border bg-background px-2 py-1 text-xs", className)}>
      <span className="text-muted-foreground">流切换</span>
      <button
        type="button"
        className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
        onClick={onPrev}
        disabled={disabled || !hasPrev}
        title={title}
      >
        ‹
      </button>
      <span className="min-w-[11rem] px-1 text-center font-mono text-foreground" title={title}>
        第 {ordinalLabel} 条 / stream eq {streamId}
      </span>
      <button
        type="button"
        className="rounded border border-border bg-accent p-1 text-muted-foreground hover:bg-accent/80 hover:text-foreground disabled:opacity-40"
        onClick={onNext}
        disabled={disabled || !hasNext}
        title={title}
      >
        ›
      </button>
      <input
        value={streamInput}
        onChange={(event) => onStreamInputChange(event.target.value.replace(/[^0-9]/g, ""))}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            onSubmitStream();
          }
        }}
        className="w-16 rounded border border-border bg-card px-1 py-0.5 text-center font-mono outline-none"
        placeholder="stream"
        title={title}
        disabled={disabled}
      />
    </div>
  );
}

export function ViewModeToggle<T extends string>({
  label = "显示方式",
  value,
  options,
  onChange,
  className,
}: {
  label?: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-xs font-medium text-muted-foreground", className)}>
      <span>{label}:</span>
      <div className="flex rounded-md border border-border bg-accent p-0.5">
        {options.map((option) => (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={cn(
              "rounded-sm px-2 py-0.5 text-xs transition-colors",
              value === option.value ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {option.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export function StreamControlBar({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("flex shrink-0 flex-wrap items-center gap-3 border-t border-border bg-white px-4 py-3 shadow-sm", className)}>
      {children}
    </div>
  );
}

export function StreamSearchBar({
  value,
  onChange,
  onPrev,
  onNext,
  matchCount,
  resultCount,
  currentIndex,
  resultLabel = "片段",
  placeholder = "搜索流内容...",
  disabled,
  className,
}: {
  value: string;
  onChange: (value: string) => void;
  onPrev: () => void;
  onNext: () => void;
  matchCount: number;
  resultCount?: number;
  currentIndex?: number;
  resultLabel?: string;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}) {
  const hasResultSummary = typeof resultCount === "number";
  const hasActiveResult = hasResultSummary && resultCount > 0 && typeof currentIndex === "number";
  const resultSummary = hasActiveResult
    ? `第 ${Math.min(currentIndex + 1, resultCount)} / ${resultCount} ${resultLabel} · ${matchCount} 匹配`
    : hasResultSummary
      ? `${resultCount} ${resultLabel} · ${matchCount} 匹配`
      : `${matchCount} 匹配`;
  const navigationDisabled = disabled || (hasResultSummary && resultCount <= 0);

  return (
    <div className={cn("flex flex-wrap items-center gap-2", className)}>
      <div className="flex w-72 items-center overflow-hidden rounded-md border border-border bg-background shadow-sm transition-colors focus-within:border-blue-500">
        <Search className="ml-2 h-4 w-4 text-muted-foreground" />
        <input
          value={value}
          onChange={(event) => onChange(event.target.value)}
          type="text"
          className="flex-1 border-none bg-transparent px-2 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none"
          placeholder={placeholder}
        />
      </div>
      <button
        type="button"
        className="rounded-md border border-border bg-background p-1.5 text-muted-foreground shadow-sm hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-45"
        onClick={onPrev}
        disabled={navigationDisabled}
      >
        <ChevronLeft className="h-4 w-4" />
      </button>
      <button
        type="button"
        className="rounded-md border border-border bg-background p-1.5 text-muted-foreground shadow-sm hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-45"
        onClick={onNext}
        disabled={navigationDisabled}
      >
        <ChevronRight className="h-4 w-4" />
      </button>
      <span className="px-2 text-xs font-medium text-muted-foreground">{resultSummary}</span>
    </div>
  );
}

export function HighlightedPayloadText({ text, highlight }: { text: string; highlight?: string }) {
  return <>{renderHighlightedText(text, highlight)}</>;
}

export function StreamCurrentChunkPanel({
  title = "当前片段",
  description,
  badge,
  chips = [],
  content,
  highlight,
  emptyText = "选择左侧片段后，可在这里固定查看详情。",
  showOpenButton,
  openButtonLabel = "查看完整 payload",
  onOpen,
  className,
}: {
  title?: ReactNode;
  description?: ReactNode;
  badge?: ReactNode;
  chips?: ReactNode[];
  content?: string | null;
  highlight?: string;
  emptyText?: ReactNode;
  showOpenButton?: boolean;
  openButtonLabel?: string;
  onOpen?: () => void;
  className?: string;
}) {
  const hasContent = Boolean(content);

  return (
    <div className={cn("overflow-hidden rounded-[24px] border border-white/80 bg-white/88 p-5 shadow-[0_22px_55px_rgba(148,163,184,0.16)] backdrop-blur-xl", className)}>
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-semibold tracking-tight text-slate-900">{title}</div>
          {description ? <div className="mt-1 text-[11px] leading-5 text-slate-500">{description}</div> : null}
        </div>
        {badge ? <div className="shrink-0">{badge}</div> : null}
      </div>

      {hasContent ? (
        <>
          {chips.length > 0 ? (
            <div className="mb-3 flex flex-wrap gap-2 text-[11px]">
              {chips.map((chip, index) => (
                <span key={index} className="rounded-full border border-slate-200 bg-white/90 px-2.5 py-1 text-slate-500 shadow-sm">
                  {chip}
                </span>
              ))}
            </div>
          ) : null}
          <div className="max-h-[380px] overflow-auto rounded-2xl border border-slate-100 bg-slate-50/75 p-3 shadow-inner shadow-slate-200/40">
            <pre className="whitespace-pre-wrap break-all font-mono text-xs leading-5 text-slate-800"><HighlightedPayloadText text={content ?? ""} highlight={highlight} /></pre>
          </div>
          {showOpenButton && onOpen ? (
            <button
              type="button"
              className="mt-3 rounded-full border border-slate-200 bg-white/90 px-3 py-1.5 text-xs font-medium text-slate-500 shadow-sm transition-all hover:border-violet-200 hover:bg-violet-50 hover:text-violet-700"
              onClick={onOpen}
            >
              {openButtonLabel}
            </button>
          ) : null}
        </>
      ) : (
        <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50/70 px-3 py-8 text-center text-xs leading-6 text-slate-500">
          {emptyText}
        </div>
      )}
    </div>
  );
}

export function StreamChunkCard({
  directionLabel,
  packetId,
  rendered,
  highlight,
  selected,
  tone,
  onSelect,
  onOpen,
  truncated,
  minHeight = "min-h-[164px]",
  className,
}: {
  directionLabel: ReactNode;
  packetId: number;
  rendered: string;
  highlight?: string;
  selected: boolean;
  tone: string;
  onSelect: () => void;
  onOpen?: () => void;
  truncated?: boolean;
  minHeight?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex min-w-0 cursor-pointer flex-col rounded-2xl border px-3 py-2 shadow-sm transition-[border-color,box-shadow,transform] duration-200 hover:-translate-y-0.5 hover:shadow-md",
        minHeight,
        tone,
        selected && "ring-2 ring-violet-200 shadow-[0_18px_38px_rgba(99,102,241,0.14)]",
        className,
      )}
      onClick={onSelect}
    >
      <div className="mb-1 flex items-center justify-between gap-3 text-[11px] font-semibold opacity-80">
        <span className="mr-2 select-none">{directionLabel}</span>
        <span className="shrink-0">packet #{packetId}</span>
      </div>
      <pre className="mt-1 min-w-0 flex-1 overflow-hidden whitespace-pre-wrap break-all text-xs leading-5"><HighlightedPayloadText text={rendered} highlight={highlight} /></pre>
      {truncated && onOpen ? (
        <div className="mt-2 flex justify-end text-[11px] opacity-80">
          <button
            type="button"
            className="rounded border border-current/20 px-2 py-1 hover:opacity-100"
            onClick={(event) => {
              event.stopPropagation();
              onOpen();
            }}
          >
            查看完整 payload
          </button>
        </div>
      ) : null}
    </div>
  );
}

function renderHighlightedText(text: string, query?: string) {
  const needle = query?.trim();
  if (!needle) return text;

  const lowerText = text.toLowerCase();
  const lowerNeedle = needle.toLowerCase();
  const parts: ReactNode[] = [];
  let cursor = 0;
  let matchIndex = lowerText.indexOf(lowerNeedle);

  while (matchIndex >= 0) {
    if (matchIndex > cursor) {
      parts.push(text.slice(cursor, matchIndex));
    }
    const end = matchIndex + needle.length;
    parts.push(
      <mark key={`${matchIndex}-${end}`} className="rounded bg-amber-200/90 px-0.5 text-inherit ring-1 ring-amber-300/70">
        {text.slice(matchIndex, end)}
      </mark>,
    );
    cursor = end;
    matchIndex = lowerText.indexOf(lowerNeedle, cursor);
  }

  if (cursor < text.length) {
    parts.push(text.slice(cursor));
  }
  return parts;
}

export function StreamPayloadDialog({
  title,
  subtitle,
  content,
  highlight,
  meta,
  extraActions,
  filename = "stream-payload.txt",
  onClose,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  content: string;
  highlight?: string;
  meta?: Array<{ label: string; value: ReactNode }>;
  extraActions?: ReactNode;
  filename?: string;
  onClose: () => void;
}) {
  const safeContent = content || "(empty payload)";
  const visibleMeta = (meta ?? []).filter((item) => item.value !== null && item.value !== undefined && item.value !== "");

  const copyContent = () => {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    void navigator.clipboard.writeText(safeContent);
  };

  const exportContent = () => {
    if (typeof document === "undefined" || typeof URL === "undefined") return;
    const blob = new Blob([safeContent], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="absolute inset-0 z-20 flex items-center justify-center bg-slate-100/75 px-6 py-8 backdrop-blur-[2px]">
      <div className="flex h-full max-h-[82vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-[0_28px_80px_-36px_rgba(15,23,42,0.6)]">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 bg-white px-4 py-3">
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-slate-950">{title}</div>
            {subtitle ? <div className="mt-1 text-[11px] leading-4 text-slate-500">{subtitle}</div> : null}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {extraActions}
            <button
              type="button"
              onClick={copyContent}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 shadow-sm transition-colors hover:bg-slate-50 hover:text-slate-900"
            >
              <Copy className="h-3.5 w-3.5" /> 复制
            </button>
            <button
              type="button"
              onClick={exportContent}
              className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 shadow-sm transition-colors hover:bg-slate-50 hover:text-slate-900"
            >
              <Download className="h-3.5 w-3.5" /> 导出
            </button>
            <button
              type="button"
              className="rounded-md p-1.5 text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900"
              onClick={onClose}
              title="关闭"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
        {visibleMeta.length > 0 ? (
          <div className="grid gap-2 border-b border-slate-100 bg-slate-50/70 px-4 py-3 text-[11px] sm:grid-cols-2 lg:grid-cols-4">
            {visibleMeta.map((item) => (
              <div key={item.label} className="min-w-0 rounded-lg border border-slate-200 bg-white px-2.5 py-2">
                <div className="font-semibold text-slate-400">{item.label}</div>
                <div className="mt-1 truncate font-mono text-slate-700" title={typeof item.value === "string" || typeof item.value === "number" ? String(item.value) : undefined}>
                  {item.value}
                </div>
              </div>
            ))}
          </div>
        ) : null}
        <div className="min-h-0 flex-1 overflow-auto bg-slate-50/80 p-4 font-mono text-xs leading-5 text-slate-800">
          <pre className="whitespace-pre-wrap break-all"><HighlightedPayloadText text={safeContent} highlight={highlight} /></pre>
        </div>
      </div>
    </div>
  );
}
