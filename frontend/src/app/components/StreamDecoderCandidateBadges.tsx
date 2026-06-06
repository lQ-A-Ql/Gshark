import type { ReactNode } from "react";
import type { StreamPayloadCandidate } from "../core/types";
import { candidateHintBadges } from "./StreamDecoderWorkbenchUtils";
import { getWebShellMetadataSummary } from "./webShellMetadata";

export function StreamDecoderCandidateBadges({ candidate }: { candidate: StreamPayloadCandidate }) {
  const metadata = getWebShellMetadataSummary(candidate, candidate.confidence);
  return (
    <div className="flex flex-wrap items-center gap-2">
      <CandidateBadge tone="blue">{candidate.kind}</CandidateBadge>
      {typeof candidate.confidence === "number" && candidate.confidence > 0 && (
        <CandidateBadge tone="emerald">{candidate.confidence}%</CandidateBadge>
      )}
      {candidate.paramName && <CandidateBadge tone="muted">{candidate.paramName}</CandidateBadge>}
      {metadata.familyLabel && <CandidateBadge tone="cyan">{metadata.familyLabel}</CandidateBadge>}
      {metadata.roleLabel !== "未标注" && <CandidateBadge tone="emerald">{metadata.roleLabel}</CandidateBadge>}
      {candidateHintBadges(candidate).map((badge) => (
        <CandidateBadge key={`${candidate.id}-${badge}`} tone="amber">
          {badge}
        </CandidateBadge>
      ))}
    </div>
  );
}

function CandidateBadge({
  children,
  tone,
}: {
  children: ReactNode;
  tone: "amber" | "blue" | "cyan" | "emerald" | "muted";
}) {
  const style = {
    amber: "border-amber-200 bg-amber-50 font-mono text-amber-700",
    blue: "border-blue-200 bg-blue-50 text-blue-700",
    cyan: "border-cyan-200 bg-cyan-50 text-cyan-700",
    emerald: "border-emerald-200 bg-emerald-50 text-emerald-700",
    muted: "border-border bg-background font-mono text-muted-foreground",
  }[tone];
  return <span className={`rounded-md border px-2 py-1 text-[11px] font-semibold ${style}`}>{children}</span>;
}
