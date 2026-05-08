import { useEffect, useMemo, useState } from "react";
import { Button } from "../../components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "../../components/ui/dialog";
import { ErrorBlock } from "../ui";
import {
  parseWinRMExtractEntries,
  renderWinRMPreviewMode,
  winrmPreviewModeLabels,
  winrmPreviewModes,
  type WinRMPreviewMode,
} from "./WinRMPreviewUtils";

interface WinRMPreviewDialogProps {
  error: string;
  loading: boolean;
  onOpenChange: (open: boolean) => void;
  open: boolean;
  text: string;
  title: string;
}

export function WinRMPreviewDialog({ error, loading, onOpenChange, open, text, title }: WinRMPreviewDialogProps) {
  const [previewMode, setPreviewMode] = useState<WinRMPreviewMode>("extract");
  const extractEntries = useMemo(() => parseWinRMExtractEntries(text), [text]);
  const displayText = useMemo(() => {
    if (previewMode === "full") {
      return text;
    }
    return renderWinRMPreviewMode(extractEntries, previewMode);
  }, [extractEntries, previewMode, text]);

  useEffect(() => {
    if (open) {
      setPreviewMode("extract");
    }
  }, [open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-6xl overflow-hidden p-0">
        <DialogHeader className="border-b border-slate-100 px-6 py-5">
          <DialogTitle>{title}结果预览</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 bg-slate-50/50 px-6 py-5">
          {error && <ErrorBlock message={error} />}
          {!loading && !error && (
            <div className="flex flex-wrap items-center gap-2">
              {winrmPreviewModes.map((mode) => (
                <Button
                  key={mode}
                  variant={previewMode === mode ? "default" : "outline"}
                  size="sm"
                  onClick={() => setPreviewMode(mode)}
                  className={previewMode === mode ? "shadow-sm" : "bg-white"}
                >
                  {winrmPreviewModeLabels[mode]}
                </Button>
              ))}
              {extractEntries.length > 0 && (
                <span className="ml-2 inline-flex items-center rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-600 shadow-sm">
                  已解析 {extractEntries.length} 个提取块
                </span>
              )}
            </div>
          )}
          {loading ? (
            <div className="rounded-lg border border-slate-200 bg-white px-4 py-8 text-center text-sm font-medium text-slate-500 shadow-sm">
              正在加载完整结果...
            </div>
          ) : (
            <pre className="max-h-[68vh] min-w-0 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-slate-200 bg-white p-5 font-mono text-[13px] leading-relaxed text-slate-800 shadow-sm selection:bg-sky-100">
              {displayText || "(empty result)"}
            </pre>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
