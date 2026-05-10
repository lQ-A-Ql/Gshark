import type { SpeechBatchTaskStatus } from "../../core/types";

interface BatchTranscriptionStatusPanelProps {
  batchStatus: SpeechBatchTaskStatus;
}

export function BatchTranscriptionStatusPanel({ batchStatus }: BatchTranscriptionStatusPanelProps) {
  if (!batchStatus.taskId) {
    return null;
  }

  const progress =
    batchStatus.total > 0
      ? ((batchStatus.completed + batchStatus.failed + batchStatus.skipped) / batchStatus.total) * 100
      : 0;

  return (
    <div className="mb-3 rounded border border-border bg-card px-3 py-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-foreground">批量音频转写</div>
          <div className="mt-1 text-xs text-muted-foreground">
            {batchStatus.done
              ? batchStatus.cancelled
                ? "任务已取消"
                : "任务已完成"
              : batchStatus.currentLabel
                ? `当前处理：${batchStatus.currentLabel}`
                : "正在准备队列..."}
          </div>
        </div>
        <div className="text-right text-xs text-muted-foreground">
          <div>
            {batchStatus.completed + batchStatus.skipped} / {batchStatus.total}
          </div>
          <div>
            失败 {batchStatus.failed} · 排队 {batchStatus.queued}
          </div>
        </div>
      </div>
      <div className="mb-2 h-2 w-full overflow-hidden rounded bg-muted">
        <div className="h-full bg-rose-600 transition-all" style={{ width: `${Math.max(0, Math.min(100, progress))}%` }} />
      </div>
      <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
        <span className="rounded bg-muted px-2 py-1">完成 {batchStatus.completed}</span>
        <span className="rounded bg-muted px-2 py-1">跳过 {batchStatus.skipped}</span>
        <span className="rounded bg-muted px-2 py-1">运行中 {batchStatus.running}</span>
        <span className="rounded bg-muted px-2 py-1">失败 {batchStatus.failed}</span>
      </div>
    </div>
  );
}
