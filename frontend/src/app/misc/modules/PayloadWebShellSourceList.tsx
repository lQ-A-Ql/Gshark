import { Link2 } from "lucide-react";
import { AnalysisBadge } from "../../components/analysis/AnalysisPrimitives";
import type { StreamPayloadSource } from "../../core/types";
import { EvidenceActions } from "../EvidenceActions";
import { FilterActions } from "../FilterActions";
import {
  formatPayloadWebShellPacketList,
  getPayloadWebShellLocationLabel,
  getPayloadWebShellMethodLabel,
  getPayloadWebShellPreviewText,
  getPayloadWebShellRuleReasons,
  getPayloadWebShellSignals,
  getPayloadWebShellSourceBadges,
  getPayloadWebShellSourceKey,
  isPayloadWebShellSourceSelected,
} from "./PayloadWebShellSourceUtils";

interface PayloadWebShellSourceListProps {
  hasCapture: boolean;
  loading: boolean;
  error: string;
  sources: StreamPayloadSource[];
  selectedSource: StreamPayloadSource | null;
  onSelect: (source: StreamPayloadSource) => void;
}

export function PayloadWebShellSourceList({
  hasCapture,
  loading,
  error,
  sources,
  selectedSource,
  onSelect,
}: PayloadWebShellSourceListProps) {
  if (!hasCapture) {
    return (
      <div className="gshark-tile mb-3 border-slate-100 bg-slate-50/80 px-3 py-2 text-xs leading-5 text-slate-500">
        可先手动粘贴 payload；打开抓包后这里会列出可疑 HTTP URI / 参数来源，并可一键填入输入区。
      </div>
    );
  }
  if (loading) {
    return (
      <div className="gshark-tile mb-3 border-cyan-100 bg-cyan-50/70 px-3 py-2 text-xs font-medium text-cyan-800">
        正在扫描当前抓包中的可疑 URI / 参数来源...
      </div>
    );
  }
  if (error) {
    return (
      <div className="gshark-tile mb-3 border-amber-200 bg-amber-50 px-3 py-2 text-xs font-medium text-amber-800">
        {error}
      </div>
    );
  }
  if (sources.length === 0) {
    return (
      <div className="gshark-tile mb-3 border-slate-100 bg-slate-50/80 px-3 py-2 text-xs leading-5 text-slate-500">
        当前抓包未发现高置信 WebShell payload 候选；仍可手动粘贴 HTTP 报文或参数值继续分析。
      </div>
    );
  }
  return (
    <div className="gshark-tile mb-3 overflow-hidden border-cyan-100">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-cyan-50 bg-cyan-50/60 px-3 py-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-cyan-900">
          <Link2 className="h-3.5 w-3.5" />
          可疑 URI / 参数来源
        </div>
        <AnalysisBadge tone="cyan">{sources.length} 条候选</AnalysisBadge>
      </div>
      <div className="max-h-72 divide-y divide-slate-100 overflow-auto">
        {sources.map((source) => {
          const selected = isPayloadWebShellSourceSelected(source, selectedSource);
          return (
            <div
              key={getPayloadWebShellSourceKey(source)}
              className={selected ? "bg-cyan-50/60 px-3 py-3" : "px-3 py-3"}
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <button type="button" onClick={() => onSelect(source)} className="min-w-0 flex-1 text-left">
                  <div className="flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-900">
                    <span>{getPayloadWebShellMethodLabel(source)}</span>
                    <span className="truncate font-mono text-cyan-700">{getPayloadWebShellLocationLabel(source)}</span>
                    {getPayloadWebShellSourceBadges(source).map((badge) => (
                      <AnalysisBadge key={badge.key} tone={badge.tone}>
                        {badge.label}
                      </AnalysisBadge>
                    ))}
                  </div>
                  <div className="mt-1 line-clamp-2 font-mono text-[11px] leading-5 text-slate-500">
                    {getPayloadWebShellPreviewText(source)}
                  </div>
                  {getPayloadWebShellRuleReasons(source).length > 0 ? (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {getPayloadWebShellRuleReasons(source).map((reason) => (
                        <span key={reason} className="bg-amber-50 px-2 py-0.5 text-[10px] font-semibold text-amber-700">
                          {reason}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {getPayloadWebShellSignals(source).map((signal) => (
                      <span key={signal} className="bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-600">
                        {signal}
                      </span>
                    ))}
                  </div>
                  <div className="mt-2 grid gap-1 text-[10px] leading-4 text-slate-400 sm:grid-cols-3">
                    <span>first: {source.firstTime || "--"}</span>
                    <span>last: {source.lastTime || "--"}</span>
                    <span>packets: {formatPayloadWebShellPacketList(source.relatedPackets, source.packetId)}</span>
                  </div>
                </button>
                <div className="flex shrink-0 flex-col items-start gap-2">
                  <EvidenceActions
                    packetId={source.packetId}
                    preferredProtocol="HTTP"
                    className="flex-col items-start"
                  />
                  {source.streamId ? <FilterActions protocol="tcp" streamId={source.streamId} /> : null}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
