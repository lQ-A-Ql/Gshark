import { AnalysisBadge, AnalysisDataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import { EvidenceActions } from "../../misc/EvidenceActions";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { confidenceColor, moduleLabel, severityTone } from "./evidencePanelRules";

interface EvidenceStatusMessageProps {
  error: string | null;
  loading: boolean;
}

export function EvidenceStatusMessage({ error, loading }: EvidenceStatusMessageProps) {
  if (loading) {
    return (
      <div className="gshark-tile mb-3 border-indigo-100 bg-indigo-50/60 px-3 py-2.5 text-xs font-medium text-slate-500">
        正在聚合跨模块证据...
      </div>
    );
  }

  if (error) {
    return (
      <div className="gshark-tile mb-3 border-amber-200 bg-amber-50/80 px-3 py-2.5 text-xs text-amber-700">{error}</div>
    );
  }

  return null;
}

interface EvidenceTableProps {
  loading: boolean;
  records: UnifiedEvidenceRecord[];
}

export function EvidenceTable({ loading, records }: EvidenceTableProps) {
  return (
    <AnalysisDataTable
      columns={[
        {
          key: "severity",
          header: "等级",
          widthClassName: "w-16",
          render: (item) => <AnalysisBadge tone={severityTone(item.severity)}>{item.severity}</AnalysisBadge>,
        },
        {
          key: "module",
          header: "模块",
          widthClassName: "w-24",
          render: (item) => <span className="text-[11px] font-medium text-slate-600">{moduleLabel(item.module)}</span>,
        },
        {
          key: "sourceType",
          header: "类型",
          widthClassName: "w-28",
          cellClassName: "font-mono text-slate-600 text-[11px]",
          render: (item) => item.sourceType || "--",
        },
        {
          key: "summary",
          header: "摘要",
          render: (item) => (
            <div className="min-w-0">
              <div className="truncate text-[13px]">{item.summary || "--"}</div>
              {item.value && <div className="mt-0.5 truncate text-[11px] text-slate-500">{item.value}</div>}
            </div>
          ),
        },
        {
          key: "confidence",
          header: "置信",
          widthClassName: "w-16",
          render: (item) =>
            item.confidence != null ? (
              <span className={cn("text-[11px] font-medium", confidenceColor(item.confidence))}>{item.confidence}</span>
            ) : (
              <span className="text-[11px] text-slate-400">--</span>
            ),
        },
        {
          key: "packetId",
          header: "包号",
          widthClassName: "w-20",
          cellClassName: "font-mono text-slate-500 text-[11px]",
          render: (item) =>
            item.packetId ? <EvidenceActions packetId={item.packetId} className="inline-flex" /> : "--",
        },
        {
          key: "tags",
          header: "标签",
          widthClassName: "w-40",
          render: (item) => <EvidenceTags tags={item.tags} />,
        },
      ]}
      data={records}
      rowKey={(item) => item.id}
      maxHeightClassName="max-h-[600px]"
      tableClassName="min-w-[900px]"
      emptyText={loading ? "正在加载..." : "当前抓包未产生证据记录"}
    />
  );
}

function EvidenceTags({ tags }: { tags: string[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {tags.slice(0, 3).map((tag) => (
        <span key={tag} className="border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-600">
          {tag}
        </span>
      ))}
      {tags.length > 3 && <span className="text-[10px] text-slate-400">+{tags.length - 3}</span>}
    </div>
  );
}
