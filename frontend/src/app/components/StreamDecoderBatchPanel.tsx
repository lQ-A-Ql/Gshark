import { LabeledInput } from "./StreamDecoderWorkbenchParts";
import {
  clampBatchOrdinal,
  MAX_BATCH_FAILURE_DETAILS,
  type BatchDecodeProgress,
  type BatchItem,
} from "./StreamDecoderWorkbenchUtils";

export function StreamDecoderBatchPanel({
  batchItems,
  batchCount,
  selectedBatchOrdinal,
  rangeStart,
  rangeEnd,
  batchProgress,
  batchFailureDetails,
  onRangeStartChange,
  onRangeEndChange,
}: {
  batchItems?: BatchItem[];
  batchCount: number;
  selectedBatchOrdinal: number;
  rangeStart: string;
  rangeEnd: string;
  batchProgress: BatchDecodeProgress | null;
  batchFailureDetails: string[];
  onRangeStartChange: (value: string) => void;
  onRangeEndChange: (value: string) => void;
}) {
  const clampedStart = clampBatchOrdinal(rangeStart, batchCount);
  const clampedEnd = clampBatchOrdinal(rangeEnd, batchCount);
  const startItem = batchItems?.[Math.min(batchCount - 1, Math.max(0, clampedStart - 1))];

  return (
    <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-foreground">批量解码区间</div>
          <div className="text-xs text-muted-foreground">
            选中任一解码器后，会对指定区间内的 payload 逐条解码，并覆盖原 payload 后持久化。
          </div>
        </div>
        <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
          当前片段位于第 {selectedBatchOrdinal} / {batchCount} 条
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-[120px_120px_minmax(0,1fr)]">
        <LabeledInput label="起始序号" value={rangeStart} onChange={onRangeStartChange} placeholder="1" />
        <LabeledInput label="结束序号" value={rangeEnd} onChange={onRangeEndChange} placeholder={String(batchCount)} />
        <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
          将按当前列表顺序处理第 {clampedStart} 到 {clampedEnd} 条。
          {batchItems && batchItems.length > 0 && (
            <div className="mt-1 truncate text-foreground" title={startItem?.label}>
              起点: {startItem?.label ?? "--"}
            </div>
          )}
        </div>
      </div>

      {batchProgress && <BatchProgress progress={batchProgress} />}
      {batchFailureDetails.length > 0 && <BatchFailureList items={batchFailureDetails} />}
    </div>
  );
}

function BatchProgress({ progress }: { progress: BatchDecodeProgress }) {
  const percent = progress.total > 0 ? Math.min(100, Math.round((progress.done / progress.total) * 100)) : 0;
  return (
    <div className="mt-3 rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span>
          进度：{progress.done}/{progress.total}
        </span>
        <span>
          成功：{progress.success} · 失败：{progress.failed}
        </span>
      </div>
      {progress.total > 0 && (
        <div className="mt-2 h-2 w-full overflow-hidden rounded bg-muted">
          <div className="h-full bg-blue-500 transition-all" style={{ width: `${percent}%` }} />
        </div>
      )}
      {progress.currentLabel && (
        <div className="mt-2 truncate text-foreground" title={progress.currentLabel}>
          当前：{progress.currentLabel}
        </div>
      )}
    </div>
  );
}

function BatchFailureList({ items }: { items: string[] }) {
  return (
    <div className="mt-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700">
      <div className="font-semibold">批量失败明细（最多显示 {MAX_BATCH_FAILURE_DETAILS} 条）</div>
      <ul className="mt-2 max-h-40 list-disc space-y-1 overflow-auto pl-4">
        {items.map((item, idx) => (
          <li key={`${idx}-${item}`}>{item}</li>
        ))}
      </ul>
    </div>
  );
}
