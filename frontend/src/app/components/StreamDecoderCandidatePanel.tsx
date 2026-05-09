import type { StreamDecoderKind, StreamPayloadCandidate, StreamPayloadInspection } from "../core/types";
import { ApplyModeButton } from "./StreamDecoderWorkbenchParts";
import { asKnownDecoder, candidateHintBadges, type DecoderApplyMode } from "./StreamDecoderWorkbenchUtils";

export function StreamDecoderCandidatePanel({
  inspection,
  inspectionLoading,
  inspectionError,
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
  selectedCandidate: StreamPayloadCandidate | null;
  applyMode: DecoderApplyMode;
  canOverwrite: boolean;
  onApplyModeChange: (mode: DecoderApplyMode) => void;
  onSelectCandidate: (candidateId: string) => void;
  onRunDecoder: (decoder: StreamDecoderKind) => void;
}) {
  const candidateCount = inspection?.candidates.length ?? 0;

  return (
    <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-foreground">候选提取与指纹识别</div>
          <div className="text-xs text-muted-foreground">
            自动从当前 payload 中提取 HTTP body / 表单参数 / Base64 / Hex 候选，并给出 webshell 家族提示。
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {inspection?.suggestedFamily && (
            <span className="rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 text-[11px] font-semibold text-cyan-700">
              家族：{inspection.suggestedFamily}
            </span>
          )}
          {inspection?.suggestedDecoder && (
            <button
              type="button"
              className="rounded-md border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] font-semibold text-blue-700 hover:bg-blue-100"
              onClick={() => runSuggestedDecoder(inspection.suggestedDecoder, onRunDecoder)}
            >
              推荐解码：{inspection.suggestedDecoder}
            </button>
          )}
          {typeof inspection?.confidence === "number" && inspection.confidence > 0 && (
            <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
              置信度 {inspection.confidence}%
            </span>
          )}
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground">覆盖策略</span>
        <ApplyModeButton label="仅预览" active={applyMode === "preview"} onClick={() => onApplyModeChange("preview")} />
        <ApplyModeButton
          label="衍生视图"
          active={applyMode === "derived"}
          onClick={() => onApplyModeChange("derived")}
        />
        {canOverwrite ? (
          <ApplyModeButton
            label="覆盖原文"
            active={applyMode === "overwrite"}
            onClick={() => onApplyModeChange("overwrite")}
          />
        ) : (
          <span className="rounded-md border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-semibold text-amber-700">
            MISC 分析模式，不写回抓包
          </span>
        )}
        {selectedCandidate && (
          <span className="rounded-md border border-border bg-card px-2 py-1 text-[11px] text-muted-foreground">
            当前候选：{selectedCandidate.label}
          </span>
        )}
      </div>

      {inspectionLoading && (
        <div className="mt-3 rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
          正在识别候选 payload...
        </div>
      )}
      {inspectionError && (
        <div className="mt-3 rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-700">
          {inspectionError}
        </div>
      )}
      {!inspectionLoading && !inspectionError && (
        <div className="mt-3 space-y-3">
          {inspection?.reasons && inspection.reasons.length > 0 && (
            <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">
              <div className="mb-1 font-semibold text-foreground">识别依据</div>
              <div className="flex flex-wrap gap-2">
                {inspection.reasons.map((reason) => (
                  <span key={reason} className="rounded-md border border-border bg-background px-2 py-1">
                    {reason}
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {candidateCount > 0 ? (
              inspection!.candidates.map((candidate) => (
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
        </div>
      )}
    </div>
  );
}

function CandidateCard({
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
        {candidate.familyHint && (
          <span className="rounded-md border border-cyan-200 bg-cyan-50 px-2 py-1 text-[11px] font-semibold text-cyan-700">
            {candidate.familyHint}
          </span>
        )}
        {candidate.sourceRole && (
          <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-[11px] font-semibold text-emerald-700">
            {candidate.sourceRole}
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
      {(candidate.decoderHints?.length ?? 0) > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {candidate.decoderHints!.map((hint) => (
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

function runSuggestedDecoder(value: unknown, onRunDecoder: (decoder: StreamDecoderKind) => void) {
  const decoder = asKnownDecoder(value);
  if (decoder) {
    onRunDecoder(decoder);
  }
}
