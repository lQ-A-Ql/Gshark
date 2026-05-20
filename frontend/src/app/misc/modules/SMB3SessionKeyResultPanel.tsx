import { Copy, Key, Trash2 } from "lucide-react";
import { Button } from "../../components/ui/button";
import type { SMB3RandomSessionKeyResult } from "../../core/types";
import { ErrorBlock } from "../ui";

interface SMB3SessionKeyResultPanelProps {
  error: string;
  loading: boolean;
  onClearResult: () => void;
  onCopyResult: () => void | Promise<void>;
  onRun: () => void | Promise<void>;
  result: SMB3RandomSessionKeyResult | null;
}

export function SMB3SessionKeyResultPanel({
  error,
  loading,
  onClearResult,
  onCopyResult,
  onRun,
  result,
}: SMB3SessionKeyResultPanelProps) {
  return (
    <>
      <div className="flex flex-wrap items-center gap-3 pt-2">
        <Button
          onClick={() => void onRun()}
          disabled={loading}
          className="gap-2 bg-indigo-600 text-white hover:bg-indigo-700"
        >
          <Key className="h-4 w-4" />
          {loading ? "计算中..." : "生成 Session Key"}
        </Button>

        {result && (
          <>
            <div className="mx-1 h-6 w-px bg-slate-200" />
            <Button
              variant="outline"
              onClick={() => void onCopyResult()}
              disabled={!result.randomSessionKey}
              className="gap-2 text-slate-700"
            >
              <Copy className="h-4 w-4 text-blue-600" />
              复制十六进制 Key
            </Button>
            <Button
              variant="ghost"
              onClick={onClearResult}
              className="gap-2 text-rose-600 hover:bg-rose-50 hover:text-rose-700"
            >
              <Trash2 className="h-4 w-4" />
              清空
            </Button>
          </>
        )}
      </div>

      {error && (
        <div className="animate-in slide-in-from-bottom-2 duration-300 fade-in">
          <ErrorBlock message={error} />
        </div>
      )}
      {result && (
        <div className="gshark-tile mt-4 animate-in slide-in-from-bottom-2 border-indigo-100 bg-indigo-50/50 p-5 duration-300 fade-in">
          <div className="mb-2 flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-xs font-semibold text-indigo-900">
              <Key className="h-3.5 w-3.5 text-indigo-500" />
              最终 Random Session Key
            </div>
          </div>
          <pre className="whitespace-pre-wrap break-all rounded-sm border border-indigo-200/60 bg-slate-50 p-3 font-mono text-[13px] font-semibold leading-relaxed text-indigo-700 selection:bg-indigo-100">
            {result.randomSessionKey}
          </pre>
        </div>
      )}
    </>
  );
}
