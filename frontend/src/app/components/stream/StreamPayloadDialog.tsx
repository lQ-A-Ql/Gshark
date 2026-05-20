import type { ReactNode } from "react";
import { Copy, Download, X } from "lucide-react";
import { copyTextToClipboard, downloadText } from "../../utils/browserFile";
import { HighlightedPayloadText } from "./StreamPayloadHighlight";

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
  const visibleMeta = (meta ?? []).filter(
    (item) => item.value !== null && item.value !== undefined && item.value !== "",
  );

  const copyContent = () => {
    void copyTextToClipboard(safeContent);
  };

  const exportContent = () => {
    downloadText(filename, safeContent);
  };

  return (
    <div className="absolute inset-0 z-20 flex items-center justify-center bg-slate-100/75 px-6 py-8 backdrop-blur-[2px]">
      <div className="gshark-soft-fill flex h-full max-h-[82vh] w-full max-w-5xl flex-col overflow-hidden">
        <div className="gshark-workbench-panel flex flex-wrap items-start justify-between gap-3 border-b border-[var(--gshark-tile-divider)] px-4 py-3">
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-slate-950">{title}</div>
            {subtitle ? <div className="mt-1 text-[11px] leading-4 text-slate-500">{subtitle}</div> : null}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {extraActions}
            <button
              type="button"
              onClick={copyContent}
              className="gshark-control inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-600 transition-colors hover:text-slate-900"
            >
              <Copy className="h-3.5 w-3.5" /> 复制
            </button>
            <button
              type="button"
              onClick={exportContent}
              className="gshark-control inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-600 transition-colors hover:text-slate-900"
            >
              <Download className="h-3.5 w-3.5" /> 导出
            </button>
            <button
              type="button"
              className="gshark-control-ghost p-1.5 text-slate-500 transition-colors hover:text-slate-900"
              onClick={onClose}
              title="关闭"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
        {visibleMeta.length > 0 ? (
          <div className="gshark-workbench-panel grid gap-2 border-b border-[var(--gshark-tile-divider)] px-4 py-3 text-[11px] sm:grid-cols-2 lg:grid-cols-4">
            {visibleMeta.map((item) => (
              <div key={item.label} className="gshark-stream-control-cluster min-w-0 px-2.5 py-2">
                <div className="font-semibold text-slate-400">{item.label}</div>
                <div
                  className="mt-1 truncate font-mono text-slate-700"
                  title={
                    typeof item.value === "string" || typeof item.value === "number" ? String(item.value) : undefined
                  }
                >
                  {item.value}
                </div>
              </div>
            ))}
          </div>
        ) : null}
        <div className="min-h-0 flex-1 overflow-auto bg-[rgba(255,255,255,0.6)] p-4 font-mono text-xs leading-5 text-slate-800">
          <pre className="whitespace-pre-wrap break-all">
            <HighlightedPayloadText text={safeContent} highlight={highlight} />
          </pre>
        </div>
      </div>
    </div>
  );
}
