import { Binary, ClipboardPaste, Eraser, Search } from "lucide-react";
import { Button } from "../../components/ui/button";
import { AnalysisBadge, AnalysisMiniStat } from "../../components/analysis/AnalysisPrimitives";
import type { MiscModuleManifest, StreamPayloadSource } from "../../core/types";
import { PayloadWebShellSourceList } from "./PayloadWebShellSourceList";
import {
  formatPayloadWebShellInputCounts,
  formatPayloadWebShellSelectedSource,
  getPayloadWebShellModuleBadges,
  getPayloadWebShellPanelTitle,
  PAYLOAD_WEBSHELL_INPUT_DESCRIPTION,
  PAYLOAD_WEBSHELL_MINI_STATS,
  PAYLOAD_WEBSHELL_REVIEW_BADGE,
  PAYLOAD_WEBSHELL_TEXTAREA_PLACEHOLDER,
} from "./PayloadWebShellInputPanelUtils";

interface PayloadWebShellInputPanelProps {
  module: MiscModuleManifest;
  embedded: boolean;
  draft: string;
  payload: string;
  inputHint: string;
  hasCapture: boolean;
  sourcesLoading: boolean;
  sourcesError: string;
  sources: StreamPayloadSource[];
  selectedSource: StreamPayloadSource | null;
  onDraftChange: (value: string) => void;
  onSelectSource: (source: StreamPayloadSource) => void;
  onUseSample: () => void;
  onClear: () => void;
  onAnalyze: () => void;
}

export function PayloadWebShellInputPanel({
  module,
  embedded,
  draft,
  payload,
  inputHint,
  hasCapture,
  sourcesLoading,
  sourcesError,
  sources,
  selectedSource,
  onDraftChange,
  onSelectSource,
  onUseSample,
  onClear,
  onAnalyze,
}: PayloadWebShellInputPanelProps) {
  return (
    <div
      className={
        embedded
          ? "overflow-hidden rounded-2xl border border-slate-100 bg-slate-50/60"
          : "overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm"
      }
    >
      <div
        className={
          embedded
            ? "border-b border-slate-100 bg-transparent px-4 py-3"
            : "border-b border-slate-100 bg-slate-50/80 px-4 py-3"
        }
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              <Binary className="h-4 w-4 text-cyan-600" />
              {getPayloadWebShellPanelTitle(module, embedded)}
            </div>
            <p className="mt-1 max-w-3xl text-[12px] leading-6 text-slate-500">{PAYLOAD_WEBSHELL_INPUT_DESCRIPTION}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {getPayloadWebShellModuleBadges(module).map((badge) => (
                <AnalysisBadge key={badge.key} tone={badge.tone}>
                  {badge.label}
                </AnalysisBadge>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" onClick={onUseSample} className="h-8 gap-2 bg-white text-xs">
              <ClipboardPaste className="h-3.5 w-3.5" />
              示例
            </Button>
            <Button type="button" variant="outline" onClick={onClear} className="h-8 gap-2 bg-white text-xs">
              <Eraser className="h-3.5 w-3.5" />
              清空
            </Button>
            <Button
              type="button"
              onClick={onAnalyze}
              className="h-8 gap-2 bg-cyan-600 text-xs text-white shadow-sm hover:bg-cyan-700"
            >
              <Search className="h-3.5 w-3.5" />
              识别候选
            </Button>
          </div>
        </div>
      </div>
      <div className="p-4">
        <div className="mb-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {PAYLOAD_WEBSHELL_MINI_STATS.map((stat) => (
            <AnalysisMiniStat key={stat.title} title={stat.title} value={stat.value} tone={stat.tone} />
          ))}
        </div>
        <PayloadWebShellSourceList
          hasCapture={hasCapture}
          loading={sourcesLoading}
          error={sourcesError}
          sources={sources}
          selectedSource={selectedSource}
          onSelect={onSelectSource}
        />
        {selectedSource ? (
          <div className="mb-3 rounded-xl border border-cyan-100 bg-cyan-50/70 px-3 py-2 text-xs leading-5 text-cyan-900">
            {formatPayloadWebShellSelectedSource(selectedSource)}
          </div>
        ) : null}
        <textarea
          value={draft}
          onChange={(event) => onDraftChange(event.target.value)}
          placeholder={PAYLOAD_WEBSHELL_TEXTAREA_PLACEHOLDER}
          className="min-h-[180px] w-full resize-y rounded-xl border border-slate-200 bg-white/95 px-4 py-3 font-mono text-xs leading-6 text-slate-800 shadow-inner outline-none transition placeholder:text-slate-400 focus:border-cyan-300 focus:ring-4 focus:ring-cyan-100"
          spellCheck={false}
        />
        {inputHint ? (
          <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-800">
            {inputHint}
          </div>
        ) : null}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500">
          <span>{formatPayloadWebShellInputCounts(draft.length, payload.length)}</span>
          <AnalysisBadge tone="amber" className="px-2.5 py-1">
            {PAYLOAD_WEBSHELL_REVIEW_BADGE}
          </AnalysisBadge>
        </div>
      </div>
    </div>
  );
}
