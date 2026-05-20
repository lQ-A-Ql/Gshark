import type { MediaAnalysisProgress } from "../../state/hooks/useAnalysisProgress";

const MEDIA_PROGRESS_STEPS: Array<{
  key: MediaAnalysisProgress["phase"];
  label: string;
}> = [
  { key: "prepare", label: "准备" },
  { key: "scan", label: "扫描" },
  { key: "organize", label: "整理" },
  { key: "rebuild", label: "重建" },
];

interface MediaAnalysisProgressPanelProps {
  progress: MediaAnalysisProgress;
}

export function MediaAnalysisProgressPanel({ progress }: MediaAnalysisProgressPanelProps) {
  if (!progress.active) {
    return null;
  }

  return (
    <div className="gshark-soft-fill mb-0 px-3 py-3">
      <div className="mb-2 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="inline-flex rounded-sm border border-rose-200/70 bg-rose-50/60 px-2 py-0.5 font-medium text-rose-700">
              {progress.phaseLabel || "处理中"}
            </span>
            <span>{Math.round(progress.percent)}%</span>
          </div>
          <div className="mt-1 text-sm font-medium text-foreground">{progress.label || "正在分析媒体流..."}</div>
        </div>
        <div className="shrink-0 text-right text-xs text-muted-foreground">
          {progress.total > 0
            ? `${progress.current.toLocaleString()} / ${progress.total.toLocaleString()}`
            : `${progress.current.toLocaleString()}`}
        </div>
      </div>
      <div className="mb-2 h-2 w-full overflow-hidden rounded bg-muted">
        <div
          className="h-full bg-rose-600 transition-all"
          style={{
            width: `${Math.max(4, Math.min(100, progress.percent || 4))}%`,
          }}
        />
      </div>
      <div className="mb-2 grid grid-cols-4 gap-2 text-[11px] text-muted-foreground">
        {MEDIA_PROGRESS_STEPS.map((item) => {
          const active = progress.phase === item.key;
          const completed =
            ["prepare", "scan", "organize", "rebuild", "complete"].indexOf(progress.phase) >=
            MEDIA_PROGRESS_STEPS.findIndex((step) => step.key === item.key);
          return (
            <div
              key={item.key}
              className={`rounded border px-2 py-1 text-center transition-colors ${
                active
                  ? "border-rose-300/70 bg-rose-50/65 text-rose-700"
                  : completed
                    ? "border-emerald-200/70 bg-emerald-50/60 text-emerald-700"
                    : "border-slate-200/60 bg-slate-50/20"
              }`}
            >
              {item.label}
            </div>
          );
        })}
      </div>
      {progress.recent.length > 1 && (
        <div className="space-y-1 text-[11px] text-muted-foreground">
          {progress.recent.slice(0, 3).map((item, index) => (
            <div key={`${item}-${index}`} className="truncate">
              {index === 0 ? "当前" : "最近"}: {item}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
