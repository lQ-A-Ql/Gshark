import type { StreamDecoderKind, StreamPayloadCandidate, StreamPayloadInspection } from "../core/types";
import { CandidateCard } from "./StreamDecoderCandidateCard";

export function StreamDecoderCandidateGrid({
  inspection,
  selectedCandidate,
  onSelectCandidate,
  onRunDecoder,
}: {
  inspection: StreamPayloadInspection | null;
  selectedCandidate: StreamPayloadCandidate | null;
  onSelectCandidate: (candidateId: string) => void;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
}) {
  const candidates = inspection?.candidates ?? [];
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
      {candidates.length > 0 ? (
        candidates.map((candidate) => (
          <CandidateCard
            key={candidate.id}
            candidate={candidate}
            selected={selectedCandidate?.id === candidate.id}
            onSelectCandidate={onSelectCandidate}
            onRunDecoder={onRunDecoder}
          />
        ))
      ) : (
        <div className="rounded-lg border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground md:col-span-2 xl:col-span-3">
          当前片段未提取到明显候选，仍可直接对原始 payload 使用手动解码器。
        </div>
      )}
    </div>
  );
}
