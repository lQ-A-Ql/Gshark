import type { StreamPayloadCandidate } from "../core/types";

export function StreamDecoderCandidatePreview({ candidate }: { candidate: StreamPayloadCandidate }) {
  return (
    <>
      <div className="mt-2 text-xs font-semibold text-foreground">{candidate.label}</div>
      <div className="mt-1 line-clamp-3 break-all font-mono text-[11px] text-muted-foreground">
        {candidate.preview || candidate.value || "(empty)"}
      </div>
    </>
  );
}
