import { AlertTriangle, RefreshCw } from "lucide-react";

interface WorkspacePacketErrorPanelProps {
  message: string;
  captureName: string;
  displayFilter: string;
  onRetry: () => void;
}

export function WorkspacePacketErrorPanel({
  message,
  captureName,
  displayFilter,
  onRetry,
}: WorkspacePacketErrorPanelProps) {
  const trimmedFilter = displayFilter.trim();
  return (
    <div className="flex h-full min-h-0 items-center justify-center px-6">
      <div className="gshark-tile w-full max-w-2xl border-rose-200 p-5">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-rose-700">
          <AlertTriangle className="h-4 w-4" />
          数据包读取失败
        </div>
        <div className="mb-4 border border-rose-100 bg-rose-50/35 px-3 py-2 font-mono text-[12px] leading-5 text-rose-800">
          {message}
        </div>
        <div className="mb-4 grid gap-2 text-xs text-slate-600 sm:grid-cols-2">
          <PacketErrorMeta label="抓包" value={captureName || "未识别"} />
          <PacketErrorMeta label="过滤器" value={trimmedFilter || "未启用"} />
        </div>
        <button
          type="button"
          onClick={onRetry}
          className="inline-flex items-center gap-2 rounded-sm border border-rose-200 bg-transparent px-3 py-1.5 text-xs font-medium text-rose-700 transition-colors hover:bg-rose-50/45"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          重试读取当前页
        </button>
      </div>
    </div>
  );
}

function PacketErrorMeta({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-slate-200 bg-transparent px-3 py-2">
      <span className="text-slate-400">{label}</span>
      <div className="mt-1 truncate font-mono text-slate-700">{value}</div>
    </div>
  );
}
