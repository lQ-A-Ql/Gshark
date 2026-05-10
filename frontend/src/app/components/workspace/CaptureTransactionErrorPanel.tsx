import { AlertTriangle, FolderOpen, RefreshCw } from "lucide-react";

interface CaptureTransactionErrorPanelProps {
  captureName: string;
  message: string;
  hasActiveCapture: boolean;
  onRetry: () => void;
  onChooseAnother: () => void;
}

export function CaptureTransactionErrorPanel({
  captureName,
  message,
  hasActiveCapture,
  onRetry,
  onChooseAnother,
}: CaptureTransactionErrorPanelProps) {
  return (
    <div className="flex h-full min-h-0 items-center justify-center bg-amber-50/55 px-6">
      <div className="w-full max-w-2xl rounded-[20px] border border-amber-200 bg-white/94 p-6 shadow-[0_22px_55px_rgba(245,158,11,0.12)] backdrop-blur-xl">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-amber-800">
          <AlertTriangle className="h-4 w-4" />
          {hasActiveCapture ? "抓包切换失败" : "抓包打开失败"}
        </div>
        <div className="mb-4 rounded-lg border border-amber-100 bg-amber-50 px-3 py-2 font-mono text-[12px] leading-5 text-amber-900">
          {message}
        </div>
        <div className="mb-4 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
          <span className="text-slate-400">目标抓包</span>
          <div className="mt-1 truncate font-mono text-slate-700">{captureName || "未识别"}</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onRetry}
            className="inline-flex items-center gap-2 rounded-md border border-amber-200 bg-white px-3 py-1.5 text-xs font-medium text-amber-800 shadow-sm transition-colors hover:bg-amber-50"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            重试当前抓包
          </button>
          <button
            type="button"
            onClick={onChooseAnother}
            className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 shadow-sm transition-colors hover:bg-slate-50"
          >
            <FolderOpen className="h-3.5 w-3.5" />
            重新选择文件
          </button>
        </div>
      </div>
    </div>
  );
}
