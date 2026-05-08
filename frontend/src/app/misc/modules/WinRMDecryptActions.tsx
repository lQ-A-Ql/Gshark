import { Copy, Download, Play, Terminal, Trash2 } from "lucide-react";
import { Button } from "../../components/ui/button";

interface WinRMDecryptActionsProps {
  hasCapture: boolean;
  hasResult: boolean;
  loading: boolean;
  onClear: () => void;
  onCopy: () => void;
  onExport: () => void;
  onOpenPreview: () => void;
  onRun: () => void;
}

export function WinRMDecryptActions({
  hasCapture,
  hasResult,
  loading,
  onClear,
  onCopy,
  onExport,
  onOpenPreview,
  onRun,
}: WinRMDecryptActionsProps) {
  return (
    <div className="flex flex-wrap items-center gap-3 pt-2">
      <Button
        onClick={onRun}
        disabled={loading || !hasCapture}
        className="gap-2 bg-sky-600 text-white shadow-sm hover:bg-sky-700"
      >
        <Play className="h-4 w-4" fill="currentColor" />
        {loading ? "解密分析中..." : "启动提取"}
      </Button>

      {hasResult && (
        <>
          <div className="mx-1 h-6 w-px bg-slate-200" />
          <Button variant="outline" onClick={onOpenPreview} className="gap-2 text-slate-700 shadow-sm">
            <Terminal className="h-4 w-4 text-sky-600" />
            打开预览视图
          </Button>
          <Button variant="outline" onClick={onExport} className="gap-2 text-slate-700 shadow-sm">
            <Download className="h-4 w-4 text-emerald-600" />
            保存导出 TXT
          </Button>
          <Button variant="outline" onClick={onCopy} className="gap-2 text-slate-700 shadow-sm">
            <Copy className="h-4 w-4 text-blue-600" />
            复制结果
          </Button>
          <Button
            variant="ghost"
            onClick={onClear}
            className="gap-2 text-rose-600 hover:bg-rose-50 hover:text-rose-700"
          >
            <Trash2 className="h-4 w-4" />
            清空
          </Button>
        </>
      )}
    </div>
  );
}
