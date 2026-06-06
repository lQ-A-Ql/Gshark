import type { StreamPayloadCandidate } from "../core/types";
import { ApplyModeButton } from "./StreamDecoderWorkbenchParts";
import type { DecoderApplyMode } from "./StreamDecoderWorkbenchUtils";

export function StreamDecoderApplyModeControls({
  applyMode,
  canOverwrite,
  selectedCandidate,
  onApplyModeChange,
}: {
  applyMode: DecoderApplyMode;
  canOverwrite: boolean;
  selectedCandidate: StreamPayloadCandidate | null;
  onApplyModeChange: (mode: DecoderApplyMode) => void;
}) {
  return (
    <div className="mt-3 flex flex-wrap items-center gap-2">
      <span className="text-xs font-medium text-muted-foreground">覆盖策略</span>
      <ApplyModeButton label="仅预览" active={applyMode === "preview"} onClick={() => onApplyModeChange("preview")} />
      <ApplyModeButton label="衍生视图" active={applyMode === "derived"} onClick={() => onApplyModeChange("derived")} />
      {canOverwrite ? (
        <ApplyModeButton label="覆盖原文" active={applyMode === "overwrite"} onClick={() => onApplyModeChange("overwrite")} />
      ) : (
        <span className="rounded-md border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-semibold text-amber-700">MISC 分析模式，不写回抓包</span>
      )}
      {selectedCandidate && <span className="rounded-md border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground">当前候选：{selectedCandidate.label}</span>}
    </div>
  );
}
