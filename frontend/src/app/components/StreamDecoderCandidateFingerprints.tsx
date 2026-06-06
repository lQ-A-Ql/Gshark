import type { StreamPayloadCandidate } from "../core/types";

export function StreamDecoderCandidateFingerprints({ candidate }: { candidate: StreamPayloadCandidate }) {
  if ((candidate.fingerprints?.length ?? 0) === 0) {
    return null;
  }
  return (
    <div className="mt-2 flex flex-wrap gap-1">
      {candidate.fingerprints!.map((fingerprint) => (
        <span
          key={`${candidate.id}-${fingerprint}`}
          className="rounded border border-amber-200 bg-amber-50 px-2 py-0.5 text-[11px] text-amber-700"
        >
          {fingerprint}
        </span>
      ))}
    </div>
  );
}
