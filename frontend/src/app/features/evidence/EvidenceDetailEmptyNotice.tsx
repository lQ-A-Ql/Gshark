import { AlertCircle } from "lucide-react";

export function EvidenceDetailEmptyNotice() {
  return (
    <div className="meow-soft-fill flex items-start gap-2 px-3 py-2 text-xs text-slate-500">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
      详情面板仅展示当前证据实际提供的字段，缺失内容会显示 `--` 或提示未提供。
    </div>
  );
}
