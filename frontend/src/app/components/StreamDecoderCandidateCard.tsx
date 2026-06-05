import type { StreamDecoderKind, StreamPayloadCandidate } from "../core/types";
import { asKnownDecoder, candidateHintBadges } from "./StreamDecoderWorkbenchUtils";
import { getWebShellMetadataSummary } from "./webShellMetadata";

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
  const metadata = getWebShellMetadataSummary(candidate, candidate.confidence);
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
      <div className="flex flex-wrap items-center gap-2">
        <span className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] font-semibold text-blue-700">
          {candidate.kind}
        </span>
        {typeof candidate.confidence === "number" && candidate.confidence > 0 && (
          <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
            {candidate.confidence}%
          </span>
        )}
        {candidate.paramName && (
          <span className="rounded-md border border-border bg-background px-2 py-1 font-mono text-[11px] text-muted-foreground">
            {candidate.paramName}
          </span>
        )}
        {metadata.familyLabel && (
          <span className="rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 text-[11px] font-semibold text-cyan-700">
            {metadata.familyLabel}
          </span>
        )}
        {metadata.roleLabel !== "未标注" && (
          <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
            {metadata.roleLabel}
          </span>
        )}
        {candidateHintBadges(candidate).map((badge) => (
          <span
            key={`${candidate.id}-${badge}`}
            className="rounded-md border border-amber-200 bg-amber-50 px-2 py-1 font-mono text-[11px] font-semibold text-amber-700"
          >
            {badge}
          </span>
        ))}
      </div>
      <div className="mt-2 text-xs font-semibold text-foreground">{candidate.label}</div>
      <div className="mt-1 line-clamp-3 break-all font-mono text-[11px] text-muted-foreground">
        {candidate.preview || candidate.value || "(empty)"}
      </div>
      <div className="mt-2 grid gap-1 rounded-md border border-border bg-background/80 px-2.5 py-2 text-[10px] leading-4 text-muted-foreground sm:grid-cols-2">
        {metadata.fields.slice(1).map((field) => (
          <span key={`${candidate.id}-${field.key}`} className="truncate">
            <span className="font-semibold text-foreground">{field.label}:</span>{" "}
            <span>{field.value}</span>
          </span>
        ))}
      </div>
      {(candidate.decoderHints?.length ?? 0) > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {candidate.decoderHints!.map((hint) => (
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
            )
          ))}
        </div>
      )}
      {(candidate.fingerprints?.length ?? 0) > 0 && (
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
      )}
    </div>
  );
}

export function runSuggestedDecoder(value: unknown, onRunDecoder: (decoder: StreamDecoderKind) => void) {
  const decoder = asKnownDecoder(value);
  if (decoder) {
    onRunDecoder(decoder);
  }
}
