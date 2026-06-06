import type { StreamDecoderKind, StreamPayloadCandidate } from "../core/types";
import { asKnownDecoder } from "./StreamDecoderWorkbenchUtils";
import { runSuggestedDecoder } from "./streamDecoderSuggestedDecoder";

export function StreamDecoderCandidateDecoderHints({
  candidate,
  onRunDecoder,
}: {
  candidate: StreamPayloadCandidate;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
}) {
  if ((candidate.decoderHints?.length ?? 0) === 0) {
    return null;
  }
  return (
    <div className="mt-2 flex flex-wrap gap-1">
      {candidate.decoderHints!.map((hint) =>
        asKnownDecoder(hint) ? (
          <button
            key={`${candidate.id}-${hint}`}
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              runSuggestedDecoder(hint, onRunDecoder);
            }}
            className="rounded border border-blue-200 bg-blue-50 px-2 py-0.5 text-[11px] text-blue-700 hover:bg-blue-100"
          >
            {hint}
          </button>
        ) : (
          <span
            key={`${candidate.id}-${hint}`}
            className="rounded border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-600"
          >
            {hint}
          </span>
        ),
      )}
    </div>
  );
}
