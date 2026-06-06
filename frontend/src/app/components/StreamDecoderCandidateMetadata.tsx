import type { StreamPayloadCandidate } from "../core/types";
import { getWebShellMetadataSummary } from "./webShellMetadata";

export function StreamDecoderCandidateMetadata({ candidate }: { candidate: StreamPayloadCandidate }) {
  const metadata = getWebShellMetadataSummary(candidate, candidate.confidence);
  return (
    <div className="mt-2 grid gap-1 rounded-md border border-border bg-background/80 px-2.5 py-2 text-[10px] leading-4 text-muted-foreground sm:grid-cols-2">
      {metadata.fields.slice(1).map((field) => (
        <span key={`${candidate.id}-${field.key}`} className="truncate">
          <span className="font-semibold text-foreground">{field.label}:</span> <span>{field.value}</span>
        </span>
      ))}
    </div>
  );
}
