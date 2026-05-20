import type { ReactNode } from "react";
import { cn } from "../ui/utils";
import { AnalysisEmptyState } from "./AnalysisCards";
import type { AnalysisBucket } from "./analysisTone";

export function AnalysisBucketChart({
  data,
  barClassName,
  emptyText = "暂无数据",
  maxHeightClassName = "max-h-[420px]",
  labelWidthClassName = "grid-cols-[220px_1fr_72px]",
  onSelect,
}: {
  data: AnalysisBucket[];
  barClassName: string;
  emptyText?: ReactNode;
  maxHeightClassName?: string;
  labelWidthClassName?: string;
  onSelect?: (row: AnalysisBucket) => void;
}) {
  const max = Math.max(1, ...data.map((item) => item.count));
  if (data.length === 0) {
    return <AnalysisEmptyState>{emptyText}</AnalysisEmptyState>;
  }
  return (
    <div className={cn("overflow-auto", maxHeightClassName)}>
      <div className="divide-y divide-slate-200/70">
        {data.map((row) => {
          const rowContent = (
            <>
              <div className="truncate font-medium text-slate-500" title={row.label}>
                {row.label}
              </div>
              <div className="h-2 rounded-sm bg-slate-500/10">
                <div
                  className={cn("h-2 rounded-sm", barClassName)}
                  style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }}
                />
              </div>
              <div className="text-right font-mono font-semibold text-slate-700">{row.count.toLocaleString()}</div>
            </>
          );
          if (onSelect) {
            return (
              <button
                key={row.label}
                type="button"
                className={cn(
                  "grid w-full items-center gap-3 px-2 py-2 text-left text-xs transition-colors hover:bg-slate-500/5",
                  labelWidthClassName,
                )}
                onClick={() => onSelect(row)}
              >
                {rowContent}
              </button>
            );
          }
          return (
            <div
              key={row.label}
              className={cn("grid items-center gap-3 px-2 py-2 text-xs", labelWidthClassName)}
            >
              {rowContent}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function AnalysisList({
  items,
  emptyText = "暂无数据",
  maxHeightClassName = "max-h-[420px]",
}: {
  items: AnalysisBucket[];
  emptyText?: ReactNode;
  maxHeightClassName?: string;
}) {
  if (items.length === 0) {
    return <AnalysisEmptyState>{emptyText}</AnalysisEmptyState>;
  }
  return (
    <div className={cn("gshark-tile divide-y divide-slate-200/70 overflow-auto", maxHeightClassName)}>
      {items.map((item) => (
        <div
          key={`${item.label}-${item.count}`}
          className="flex items-center justify-between px-3 py-2 text-xs"
        >
          <span className="truncate font-medium text-slate-500" title={item.label}>
            {item.label}
          </span>
          <span className="ml-3 font-mono font-semibold text-slate-700">{item.count.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}
