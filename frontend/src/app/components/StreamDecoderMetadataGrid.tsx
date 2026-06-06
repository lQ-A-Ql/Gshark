import type { StreamPayloadCandidate, StreamPayloadInspection } from "../core/types";
import type { DecoderHintSource } from "./StreamDecoderTypes";
import { getWebShellMetadataSummary } from "./webShellMetadata";

export function StreamDecoderMetadataGrid({
  hintSource,
  inspection,
  selectedCandidate,
}: {
  hintSource?: DecoderHintSource;
  inspection: StreamPayloadInspection | null;
  selectedCandidate: StreamPayloadCandidate | null;
}) {
  const metadata = getWebShellMetadataSummary(
    hintSource ?? selectedCandidate ?? { familyHint: inspection?.suggestedFamily },
    inspection?.confidence ?? selectedCandidate?.confidence,
  );
  return (
    <div className="mt-3 grid gap-2 rounded-md border border-border bg-card px-3 py-2 text-[11px] leading-5 text-muted-foreground md:grid-cols-2 xl:grid-cols-5">
      {metadata.fields.map((field) => (
        <span key={field.key} className="truncate">
          <span className="font-semibold text-foreground">{field.label}:</span> <span>{field.value}</span>
        </span>
      ))}
    </div>
  );
}
