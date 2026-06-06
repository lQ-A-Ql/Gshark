import { AnalysisBadge } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import {
  confidenceColor,
  confidenceLabel,
  evidenceLocationValue,
  moduleLabel,
  severityLabel,
  severityTone,
} from "./evidencePanelRules";

export function evidenceTableColumns() {
  return [
    {
      key: "severity",
      header: "等级",
      widthClassName: "w-20",
      render: (item: UnifiedEvidenceRecord) => (
        <AnalysisBadge tone={severityTone(item.severity)}>{severityLabel(item.severity)}</AnalysisBadge>
      ),
    },
    {
      key: "module",
      header: "模块 / 类型",
      widthClassName: "w-32",
      render: (item: UnifiedEvidenceRecord) => (
        <div className="min-w-0">
          <div className="text-[11px] font-semibold text-slate-700">{moduleLabel(item.module)}</div>
          <div className="truncate font-mono text-[10px] text-slate-500">{item.sourceType || "--"}</div>
        </div>
      ),
    },
    {
      key: "summary",
      header: "调查摘要",
      render: (item: UnifiedEvidenceRecord) => (
        <div className="min-w-0">
          <div className="truncate text-[13px] font-medium text-slate-900">{item.summary || "--"}</div>
          <div className="mt-0.5 truncate text-[11px] text-slate-500">{item.value || evidenceLocationValue(item)}</div>
        </div>
      ),
    },
    {
      key: "context",
      header: "上下文",
      widthClassName: "w-44",
      render: (item: UnifiedEvidenceRecord) => (
        <div className="space-y-0.5 text-[11px] text-slate-500">
          <div>{item.feature || item.entityType || "--"}</div>
          <div className="font-mono">pkt {item.packetId ?? "--"} / str {item.streamId ?? "--"}</div>
        </div>
      ),
    },
    {
      key: "confidence",
      header: "置信",
      widthClassName: "w-20",
      render: (item: UnifiedEvidenceRecord) => (
        <div className="space-y-0.5 text-[11px]">
          <div className={cn("font-semibold", item.confidence != null ? confidenceColor(item.confidence) : "text-slate-400")}>
            {item.confidence != null ? `${item.confidence}%` : "--"}
          </div>
          <div className="text-slate-400">{confidenceLabel(item.confidenceLabel)}</div>
        </div>
      ),
    },
  ];
}
