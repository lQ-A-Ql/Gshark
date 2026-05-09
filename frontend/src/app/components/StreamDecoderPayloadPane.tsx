import { copyTextToClipboard, downloadText } from "../utils/browserFile";

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
