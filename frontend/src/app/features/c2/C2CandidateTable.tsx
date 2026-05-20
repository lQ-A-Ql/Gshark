import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";
import { EmptyState } from "../../components/DesignSystem";
import { AnalysisDataTable as DataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { C2IndicatorRecord } from "../../core/types";
import { EvidenceActions } from "../../misc/EvidenceActions";
import { CandidateFilterActions } from "./C2CandidateActions";
import { CandidateDetailPanel, CandidateTagLine } from "./C2CandidateTableDetails";
import {
  candidateRowKey,
  candidateTagValues,
  compactCandidateTags,
  preferredProtocolForCandidate,
} from "./C2CandidateTableRules";

const C2_CANDIDATE_TABLE_WRAPPER_CLASS = "border-slate-200";
const C2_CANDIDATE_TABLE_HEADER_CLASS = "gshark-tile-header bg-slate-50/80 text-slate-700";
const C2_CANDIDATE_TABLE_ROW_CLASS = "last:border-b-0 odd:bg-transparent even:bg-slate-50/45";
const C2_CANDIDATE_MONO_CELL_CLASS = "font-mono text-slate-600";

export function C2CandidateTable({ candidates }: { candidates: C2IndicatorRecord[] }) {
  const [expandedRows, setExpandedRows] = useState<Set<string>>(() => new Set());

  const toggleExpanded = (rowKey: string) => {
    setExpandedRows((current) => {
      const next = new Set(current);
      if (next.has(rowKey)) {
        next.delete(rowKey);
      } else {
        next.add(rowKey);
      }
      return next;
    });
  };

  if (candidates.length === 0) {
    return (
      <EmptyState className="py-8">
        当前抓包未形成候选证据。命中后会展示 family、channel、indicator、confidence、actorHints 与
        tags，并支持定位包或打开关联流。
      </EmptyState>
    );
  }

  return (
    <DataTable<C2IndicatorRecord>
      data={candidates}
      rowKey={(item, index) => candidateRowKey(item, index)}
      maxHeightClassName="max-h-[440px]"
      wrapperClassName={C2_CANDIDATE_TABLE_WRAPPER_CLASS}
      headerClassName={C2_CANDIDATE_TABLE_HEADER_CLASS}
      tableClassName="min-w-[1120px]"
      rowClassName={(item, index) =>
        cn(
          C2_CANDIDATE_TABLE_ROW_CLASS,
          expandedRows.has(candidateRowKey(item, index)) ? "bg-rose-50/25" : "hover:bg-slate-50/70",
        )
      }
      expandedRowClassName="border-rose-100/80 bg-rose-50/20"
      renderExpandedRow={(item, index) => {
        const tags = candidateTagValues(item);
        return expandedRows.has(candidateRowKey(item, index)) ? <CandidateDetailPanel item={item} tags={tags} /> : null;
      }}
      columns={[
        {
          key: "packet",
          header: "包号",
          widthClassName: "w-16",
          cellClassName: "font-mono text-slate-500",
          render: (item) => item.packetId || "--",
        },
        {
          key: "family",
          header: "Family",
          widthClassName: "w-20",
          cellClassName: "font-semibold text-slate-800",
          render: (item) => item.family,
        },
        { key: "channel", header: "Channel", widthClassName: "w-24", render: (item) => item.channel || "--" },
        { key: "type", header: "类型", widthClassName: "w-32", render: (item) => item.indicatorType || "--" },
        {
          key: "value",
          header: "值",
          widthClassName: "w-44",
          cellClassName: "break-all font-mono text-[11px] text-slate-600",
          render: (item) => item.indicatorValue || item.uri || item.host || "--",
        },
        {
          key: "confidence",
          header: "置信度",
          widthClassName: "w-20",
          cellClassName: C2_CANDIDATE_MONO_CELL_CLASS,
          render: (item) => item.confidence ?? "--",
        },
        {
          key: "summary",
          header: "摘要 / 标签",
          cellClassName: "space-y-2",
          render: (item, index) => {
            const rowKey = candidateRowKey(item, index);
            const expanded = expandedRows.has(rowKey);
            return (
              <>
                <div className="leading-5 text-slate-700">{item.summary || "--"}</div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    aria-label={`${expanded ? "收起" : "展开"} C2 候选详情 #${item.packetId || index + 1}`}
                    onClick={() => toggleExpanded(rowKey)}
                    className={cn(
                      "inline-flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold transition-all duration-200",
                      expanded
                        ? "border-rose-200 bg-rose-50 text-rose-700"
                        : "border-slate-200 bg-slate-50/70 text-slate-600 hover:border-rose-200 hover:bg-rose-50 hover:text-rose-700",
                    )}
                  >
                    {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                    {expanded ? "收起详情" : "展开详情"}
                  </button>
                  <CandidateTagLine values={compactCandidateTags(candidateTagValues(item))} />
                </div>
              </>
            );
          },
        },
        {
          key: "actions",
          header: "证据联动",
          widthClassName: "w-44",
          render: (item) => (
            <div className="flex flex-col items-start gap-2">
              <EvidenceActions
                packetId={item.packetId}
                preferredProtocol={preferredProtocolForCandidate(item)}
                className="flex-col items-start"
              />
              <CandidateFilterActions item={item} />
            </div>
          ),
        },
      ]}
    />
  );
}
