import type { StreamDecoderKind, StreamPayloadCandidate, StreamPayloadInspection } from "../core/types";
import type { DecoderHintSource } from "./StreamDecoderTypes";
import { StreamDecoderApplyModeControls } from "./StreamDecoderApplyModeControls";
import { StreamDecoderCandidateHeader } from "./StreamDecoderCandidateHeader";
import { StreamDecoderInspectionState } from "./StreamDecoderInspectionState";
import { StreamDecoderMetadataGrid } from "./StreamDecoderMetadataGrid";
import type { DecoderApplyMode } from "./StreamDecoderWorkbenchUtils";

export function StreamDecoderCandidatePanel({
  inspection,
  inspectionLoading,
  inspectionError,
  hintSource,
  selectedCandidate,
  applyMode,
  canOverwrite,
  onApplyModeChange,
  onSelectCandidate,
  onRunDecoder,
}: {
  inspection: StreamPayloadInspection | null;
  inspectionLoading: boolean;
  inspectionError: string;
  hintSource?: DecoderHintSource;
  selectedCandidate: StreamPayloadCandidate | null;
  applyMode: DecoderApplyMode;
  canOverwrite: boolean;
  onApplyModeChange: (mode: DecoderApplyMode) => void;
  onSelectCandidate: (candidateId: string) => void;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
}) {
  return (
    <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
      <StreamDecoderCandidateHeader hintSource={hintSource} inspection={inspection} selectedCandidate={selectedCandidate} onRunDecoder={onRunDecoder} />
      <StreamDecoderMetadataGrid hintSource={hintSource} inspection={inspection} selectedCandidate={selectedCandidate} />
      <StreamDecoderApplyModeControls applyMode={applyMode} canOverwrite={canOverwrite} selectedCandidate={selectedCandidate} onApplyModeChange={onApplyModeChange} />
      <StreamDecoderInspectionState
        inspection={inspection}
        inspectionLoading={inspectionLoading}
        inspectionError={inspectionError}
        selectedCandidate={selectedCandidate}
        onSelectCandidate={onSelectCandidate}
        onRunDecoder={onRunDecoder}
      />
    </div>
  );
}
