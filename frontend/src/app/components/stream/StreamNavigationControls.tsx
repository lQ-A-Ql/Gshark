import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight, Search } from "lucide-react";
import { cn } from "../ui/utils";

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
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-md border border-border bg-background px-2 py-1 text-xs",
        className,
      )}
    >
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
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-xs font-medium text-muted-foreground",
        className,
      )}
    >
      <span>{label}:</span>
      <div className="flex rounded-md border border-border bg-accent p-0.5">
        {options.map((option) => (
          <button
            key={option.value}
            type="button"
            onClick={() => onChange(option.value)}
            className={cn(
              "rounded-sm px-2 py-0.5 text-xs transition-colors",
              value === option.value
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground",
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
    <div
      className={cn(
        "flex shrink-0 flex-wrap items-center gap-3 border-t border-border bg-white px-4 py-3 shadow-sm",
        className,
      )}
    >
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
