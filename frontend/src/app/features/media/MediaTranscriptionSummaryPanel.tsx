import { Copy, Download } from "lucide-react";
import { useMemo } from "react";
import { AnalysisPanel as Panel } from "../../components/analysis/AnalysisPrimitives";
import type { MediaTranscription, SpeechBatchTaskStatus } from "../../core/types";

interface BatchSummaryItem {
  token: string;
  title: string;
  text: string;
  status: string;
  cached: boolean;
}

interface MediaTranscriptionSummaryPanelProps {
  batchStatus: SpeechBatchTaskStatus;
  transcriptions: Record<string, MediaTranscription>;
  onCopyText: (text: string) => void | Promise<void>;
  onExportBatchTranscription: (format: "txt" | "json") => void | Promise<void>;
}

function collectBatchSummaryItems(
  batchStatus: SpeechBatchTaskStatus,
  transcriptions: Record<string, MediaTranscription>,
): BatchSummaryItem[] {
  const byToken = new Map<string, BatchSummaryItem>();
  for (const item of batchStatus.items) {
    const text = (item.text || transcriptions[item.token]?.text || "").trim();
    if (!text) continue;
    byToken.set(item.token, {
      token: item.token,
      title: item.title || transcriptions[item.token]?.title || item.mediaLabel,
      text,
      status: item.status,
      cached: item.cached,
    });
  }
  for (const [token, item] of Object.entries(transcriptions)) {
    if (!item.text.trim() || byToken.has(token)) continue;
    byToken.set(token, {
      token,
      title: item.title,
      text: item.text,
      status: item.status,
      cached: item.cached,
    });
  }
  return Array.from(byToken.values());
}

export function MediaTranscriptionSummaryPanel({
  batchStatus,
  transcriptions,
  onCopyText,
  onExportBatchTranscription,
}: MediaTranscriptionSummaryPanelProps) {
  const batchSummaryItems = useMemo(
    () => collectBatchSummaryItems(batchStatus, transcriptions),
    [batchStatus, transcriptions],
  );

  if (batchSummaryItems.length === 0 && (!batchStatus.taskId || batchStatus.total === 0)) {
    return null;
  }

  const copyAllText = async () => {
    const text = batchSummaryItems.map((item) => `${item.title}\n${item.text}`).join("\n\n");
    if (!text.trim()) return;
    await onCopyText(text);
  };

  return (
    <Panel title={`转写汇总 (${batchSummaryItems.length})`} className="mt-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <button
          className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent disabled:opacity-60"
          onClick={() => void copyAllText()}
          disabled={batchSummaryItems.length === 0}
        >
          <Copy className="h-3.5 w-3.5" />
          复制全部
        </button>
        <button
          className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent disabled:opacity-60"
          onClick={() => void onExportBatchTranscription("txt")}
          disabled={batchSummaryItems.length === 0}
        >
          <Download className="h-3.5 w-3.5" />
          导出 TXT
        </button>
        <button
          className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-accent disabled:opacity-60"
          onClick={() => void onExportBatchTranscription("json")}
          disabled={batchSummaryItems.length === 0}
        >
          <Download className="h-3.5 w-3.5" />
          导出 JSON
        </button>
      </div>
      {batchSummaryItems.length === 0 ? (
        <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">
          批量转写结果会在这里汇总展示。
        </div>
      ) : (
        <div className="space-y-3">
          {batchSummaryItems.map((item) => (
            <details key={item.token} className="rounded border border-border bg-background" open>
              <summary className="cursor-pointer list-none px-3 py-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="text-sm font-medium">{item.title}</div>
                  <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                    <span className="rounded bg-muted px-2 py-0.5">{item.cached ? "缓存" : "新转写"}</span>
                    <span>{item.status}</span>
                  </div>
                </div>
              </summary>
              <div className="border-t border-border px-3 py-3">
                <div className="whitespace-pre-wrap text-sm text-foreground">{item.text}</div>
                <div className="mt-3">
                  <button
                    className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs hover:bg-accent"
                    onClick={() => void onCopyText(item.text)}
                  >
                    <Copy className="h-3.5 w-3.5" />
                    复制
                  </button>
                </div>
              </div>
            </details>
          ))}
        </div>
      )}
    </Panel>
  );
}
