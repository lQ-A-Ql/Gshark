import type { ReactNode } from "react";
import type { StreamDecoderKind, StreamPayloadCandidate, StreamPayloadInspection } from "../core/types";
import type { DecoderHintSource } from "./StreamDecoderTypes";
import { runSuggestedDecoder } from "./StreamDecoderCandidateCard";
import { asKnownDecoder } from "./StreamDecoderWorkbenchUtils";
import { getWebShellMetadataSummary } from "./webShellMetadata";

export function StreamDecoderCandidateHeader({
  hintSource,
  inspection,
  selectedCandidate,
  onRunDecoder,
}: {
  hintSource?: DecoderHintSource;
  inspection: StreamPayloadInspection | null;
  selectedCandidate: StreamPayloadCandidate | null;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
}) {
  const metadata = getWebShellMetadataSummary(
    hintSource ?? selectedCandidate ?? { familyHint: inspection?.suggestedFamily },
    inspection?.confidence ?? selectedCandidate?.confidence,
  );
  const supportedSuggestedDecoder = asKnownDecoder(inspection?.suggestedDecoder);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <div className="text-sm font-semibold text-foreground">候选提取与指纹识别</div>
        <div className="text-xs text-muted-foreground">自动从当前 payload 中提取 HTTP body / 表单参数 / Base64 / Hex 候选，并给出 webshell 家族提示。</div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {metadata.familyLabel && <HeaderBadge tone="cyan">家族：{metadata.familyLabel}</HeaderBadge>}
        {inspection?.suggestedDecoder && supportedSuggestedDecoder && (
          <button
            type="button"
            className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] font-semibold text-blue-700 hover:bg-blue-100"
            onClick={() => runSuggestedDecoder(inspection.suggestedDecoder, onRunDecoder)}
          >
            推荐解码：{metadata.decoderLabel}
          </button>
        )}
        {inspection?.suggestedDecoder && !supportedSuggestedDecoder && <HeaderBadge tone="amber">解码提示：{metadata.decoderLabel}</HeaderBadge>}
        {typeof inspection?.confidence === "number" && inspection.confidence > 0 && <HeaderBadge tone="emerald">置信度 {inspection.confidence}%</HeaderBadge>}
      </div>
    </div>
  );
}

function HeaderBadge({ children, tone }: { children: ReactNode; tone: "amber" | "cyan" | "emerald" }) {
  const style = {
    amber: "border-amber-200 bg-amber-50 text-amber-700",
    cyan: "border-cyan-200 bg-cyan-50 text-cyan-700",
    emerald: "border-emerald-200 bg-emerald-50 text-emerald-700",
  }[tone];
  return <span className={`rounded-md border px-2 py-1 text-[11px] font-semibold ${style}`}>{children}</span>;
}
