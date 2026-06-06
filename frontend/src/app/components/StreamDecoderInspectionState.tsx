import type { StreamDecoderKind, StreamPayloadCandidate, StreamPayloadInspection } from "../core/types";
import { StreamDecoderCandidateGrid } from "./StreamDecoderCandidateGrid";

export function StreamDecoderInspectionState({
  inspection,
  inspectionLoading,
  inspectionError,
  selectedCandidate,
  onSelectCandidate,
  onRunDecoder,
}: {
  inspection: StreamPayloadInspection | null;
  inspectionLoading: boolean;
  inspectionError: string;
  selectedCandidate: StreamPayloadCandidate | null;
  onSelectCandidate: (candidateId: string) => void;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
}) {
  if (inspectionLoading) return <div className="mt-3 rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">正在识别候选 payload...</div>;
  if (inspectionError) return <div className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700">{inspectionError}</div>;
  return (
    <div className="mt-3 space-y-3">
      {inspection?.reasons && inspection.reasons.length > 0 ? <ReasonList reasons={inspection.reasons} /> : null}
      <StreamDecoderCandidateGrid inspection={inspection} selectedCandidate={selectedCandidate} onSelectCandidate={onSelectCandidate} onRunDecoder={onRunDecoder} />
    </div>
  );
}

function ReasonList({ reasons }: { reasons: string[] }) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
      <div className="mb-1 font-semibold text-foreground">识别依据</div>
      <div className="flex flex-wrap gap-2">
        {reasons.map((reason) => <span key={reason} className="rounded-md border border-border bg-background px-2 py-1">{reason}</span>)}
      </div>
    </div>
  );
}
