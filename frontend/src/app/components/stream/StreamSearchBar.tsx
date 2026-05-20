import { ChevronLeft, ChevronRight, Search } from "lucide-react";

import { cn } from "../ui/utils";

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
      <div className="gshark-field flex w-72 items-center overflow-hidden px-2 transition-colors">
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
        className="gshark-control-ghost p-1.5 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-45"
        onClick={onPrev}
        disabled={navigationDisabled}
      >
        <ChevronLeft className="h-4 w-4" />
      </button>
      <button
        type="button"
        className="gshark-control-ghost p-1.5 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-45"
        onClick={onNext}
        disabled={navigationDisabled}
      >
        <ChevronRight className="h-4 w-4" />
      </button>
      <span className="px-2 text-xs font-medium text-muted-foreground">{resultSummary}</span>
    </div>
  );
}
