import { StreamDecoderBatchPanel } from "./StreamDecoderBatchPanel";
import { StreamDecoderCandidatePanel } from "./StreamDecoderCandidatePanel";
import { StreamDecoderPayloadGrid } from "./StreamDecoderPayloadGrid";
import { StreamDecoderWorkbenchHeader } from "./StreamDecoderWorkbenchHeader";
import { StreamDecoderSettingsPanel } from "./StreamDecoderSettingsPanel";
import { useStreamDecoderWorkbench, type StreamDecoderWorkbenchProps } from "./useStreamDecoderWorkbench";

export function StreamDecoderWorkbench({
  payload,
  inspectRevision,
  chunkLabel,
  tone = "blue",
  onApplyDecoded,
  batchItems,
  selectedBatchIndex,
  onApplyDecodedBatch,
  sourceHint,
}: StreamDecoderWorkbenchProps) {
  const state = useStreamDecoderWorkbench({
    payload,
    inspectRevision,
    chunkLabel,
    onApplyDecoded,
    batchItems,
    selectedBatchIndex,
    onApplyDecodedBatch,
    sourceHint,
  });
  const toneClass =
    tone === "amber"
      ? "border-amber-500/30 bg-amber-500/10"
      : tone === "emerald"
        ? "border-emerald-500/30 bg-emerald-500/10"
        : "border-blue-500/30 bg-blue-500/10";

  return (
    <div className={`min-w-0 rounded-xl border ${toneClass} p-4`}>
      <StreamDecoderWorkbenchHeader
        chunkLabel={chunkLabel}
        runningDecoder={state.runningDecoder}
        disabled={!state.hasPayload && !state.hasBatchMode}
        onRunDecoder={(decoder) => void state.runDecoder(decoder)}
        onOpenSettings={state.setActiveSettings}
        onCancel={state.cancelDecode}
      />

      <StreamDecoderCandidatePanel
        inspection={state.inspection}
        inspectionLoading={state.inspectionLoading}
        inspectionError={state.inspectionError}
        selectedCandidate={state.selectedCandidate}
        applyMode={state.applyMode}
        canOverwrite={state.canOverwrite}
        onApplyModeChange={state.setApplyMode}
        onSelectCandidate={state.setSelectedCandidateId}
        onRunDecoder={(decoder) => void state.runDecoder(decoder)}
      />

      {state.hasBatchMode && (
        <StreamDecoderBatchPanel
          batchItems={batchItems}
          batchCount={state.batchCount}
          selectedBatchOrdinal={state.selectedBatchOrdinal}
          rangeStart={state.rangeStart}
          rangeEnd={state.rangeEnd}
          batchProgress={state.batchProgress}
          batchFailureDetails={state.batchFailureDetails}
          onRangeStartChange={state.setRangeStart}
          onRangeEndChange={state.setRangeEnd}
        />
      )}

      {state.activeSettings && (
        <StreamDecoderSettingsPanel
          activeSettings={state.activeSettings}
          settings={state.settings}
          setSettings={state.setSettings}
          onClose={() => state.setActiveSettings(null)}
        />
      )}

      <StreamDecoderPayloadGrid
        rawPayload={payload}
        preparedPayload={state.preparedPayload}
        effectivePayload={state.effectivePayload}
        selectedCandidate={state.selectedCandidate}
        result={state.result}
        decodeError={state.decodeError}
        runningDecoder={state.runningDecoder}
        applyMessage={state.applyMessage}
      />
    </div>
  );
}
