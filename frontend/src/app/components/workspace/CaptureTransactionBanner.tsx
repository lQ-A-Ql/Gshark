import { AlertTriangle, FolderOpen, RefreshCw } from "lucide-react";

interface CaptureTransactionBannerProps {
  message: string;
  captureName: string;
  onRetry: () => void;
  onChooseAnother: () => void;
}

export function CaptureTransactionBanner({
  message,
  captureName,
  onRetry,
  onChooseAnother,
}: CaptureTransactionBannerProps) {
  return (
    <div className="gshark-tile-toolbar flex items-start justify-between gap-3 border-b border-amber-200 bg-amber-50/70 px-3 py-3 text-xs text-amber-900">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 font-semibold">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          抓包切换失败
        </div>
        <div className="mt-1 break-all font-mono">{message}</div>
        <div className="mt-1 text-[11px] text-amber-800/80">目标抓包: {captureName || "未识别"}</div>
      </div>
      <div className="flex shrink-0 gap-2">
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-1 rounded-md border border-amber-200 bg-white px-2 py-1 font-medium text-amber-800 hover:bg-amber-50"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          重试
        </button>
        <button
          type="button"
          onClick={onChooseAnother}
          className="inline-flex items-center gap-1 rounded-md border border-slate-200 bg-white px-2 py-1 font-medium text-slate-700 hover:bg-slate-50"
        >
          <FolderOpen className="h-3.5 w-3.5" />
          换文件
        </button>
      </div>
    </div>
  );
}
