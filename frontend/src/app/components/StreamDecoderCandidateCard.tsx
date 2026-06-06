import type { StreamDecoderKind, StreamPayloadCandidate } from "../core/types";
import { StreamDecoderCandidateBadges } from "./StreamDecoderCandidateBadges";
import { StreamDecoderCandidateDecoderHints } from "./StreamDecoderCandidateDecoderHints";
import { StreamDecoderCandidateFingerprints } from "./StreamDecoderCandidateFingerprints";
import { StreamDecoderCandidateMetadata } from "./StreamDecoderCandidateMetadata";
import { StreamDecoderCandidatePreview } from "./StreamDecoderCandidatePreview";
export { runSuggestedDecoder } from "./streamDecoderSuggestedDecoder";

export function CandidateCard({
  candidate,
  selected,
  onSelectCandidate,
  onRunDecoder,
}: {
  candidate: StreamPayloadCandidate;
  selected: boolean;
  onSelectCandidate: (candidateId: string) => void;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
}) {
  return (
    <div
      onClick={() => onSelectCandidate(candidate.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelectCandidate(candidate.id);
        }
      }}
      role="button"
      tabIndex={0}
      className={`rounded-lg border px-3 py-3 text-left transition-colors ${
        selected
          ? "border-blue-400 bg-blue-50 shadow-sm"
          : "border-border bg-card hover:border-blue-200 hover:bg-accent/50"
      }`}
    >
      <StreamDecoderCandidateBadges candidate={candidate} />
      <StreamDecoderCandidatePreview candidate={candidate} />
      <StreamDecoderCandidateMetadata candidate={candidate} />
      <StreamDecoderCandidateDecoderHints candidate={candidate} onRunDecoder={onRunDecoder} />
      <StreamDecoderCandidateFingerprints candidate={candidate} />
    </div>
  );
}
