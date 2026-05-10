import { Download, Filter, Search, Shield } from "lucide-react";
import { AnalysisBadge, AnalysisDataTable } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import { EvidenceActions } from "../../misc/EvidenceActions";
import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";
import {
  collectEvidenceCaveats,
  confidenceColor,
  EVIDENCE_MODULE_OPTIONS,
  EVIDENCE_SEVERITIES,
  moduleLabel,
  severityActiveStyle,
  severityLabel,
  severityTone,
} from "./evidencePanelRules";

const EVIDENCE_HERO_TAGS = ["威胁狩猎", "C2", "APT", "工控", "车机", "USB", "对象", "统一 Schema"];

export function EvidenceHero() {
  return (
    <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="min-w-0 flex-1 space-y-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-indigo-100 text-indigo-700 shadow-sm">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-baseline gap-2">
              <h1 className="text-[19px] font-bold tracking-tight text-slate-900 sm:text-[22px]">证据链总览</h1>
              <span className="text-[11px] font-semibold uppercase tracking-[0.32em] text-slate-400">
                UNIFIED EVIDENCE
              </span>
            </div>
          </div>
        </div>
        <p className="max-w-2xl text-[13px] leading-7 text-slate-500">
          跨模块统一查看威胁狩猎、C2 分析、APT 画像、工控分析、车机分析、USB
          分析和对象导出的证据记录，支持搜索、过滤和导出。
        </p>
        <div className="flex flex-wrap gap-2 text-[11px]">
          {EVIDENCE_HERO_TAGS.map((tag) => (
            <span
              key={tag}
              className="rounded-full border border-indigo-100 bg-indigo-50/60 px-3 py-1 text-indigo-700 shadow-sm"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

interface EvidenceSeveritySummaryProps {
  counts: Record<EvidenceSeverity, number>;
  severityFilter: EvidenceSeverity | "all";
  onSeverityFilterChange: (severity: EvidenceSeverity | "all") => void;
}

export function EvidenceSeveritySummary({
  counts,
  severityFilter,
  onSeverityFilterChange,
}: EvidenceSeveritySummaryProps) {
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {EVIDENCE_SEVERITIES.map((severity) => (
        <button
          key={severity}
          type="button"
          onClick={() => onSeverityFilterChange(severityFilter === severity ? "all" : severity)}
          className={cn(
            "rounded-full border px-3 py-1 text-[11px] font-medium transition-all",
            severityFilter === severity
              ? severityActiveStyle(severity)
              : "border-slate-200 bg-white/80 text-slate-600 hover:border-indigo-200",
          )}
        >
          {severityLabel(severity)} · {counts[severity] ?? 0}
        </button>
      ))}
    </div>
  );
}

interface EvidenceToolbarProps {
  evidenceCount: number;
  query: string;
  resultCount: number;
  selectedModules: string[];
  onExportCSV: () => void;
  onExportJSON: () => void;
  onQueryChange: (query: string) => void;
  onToggleModule: (module: string) => void;
}

export function EvidenceToolbar({
  evidenceCount,
  query,
  resultCount,
  selectedModules,
  onExportCSV,
  onExportJSON,
  onQueryChange,
  onToggleModule,
}: EvidenceToolbarProps) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3 rounded-2xl border border-slate-100 bg-white/80 px-4 py-3 shadow-sm">
      <div className="flex items-center gap-2 rounded-md border border-border bg-background px-2 py-1 shadow-sm focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500">
        <Search className="h-4 w-4 text-muted-foreground" />
        <input
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="搜索摘要、值、标签..."
          className="border-none bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
        />
      </div>
      <div className="flex items-center gap-2">
        <Filter className="h-4 w-4 text-muted-foreground" />
        {EVIDENCE_MODULE_OPTIONS.map((module) => (
          <EvidenceModuleButton
            key={module.value}
            active={selectedModules.includes(module.value)}
            label={module.label}
            module={module.value}
            onToggle={onToggleModule}
          />
        ))}
      </div>
      <div className="ml-auto flex items-center gap-2">
        <span className="text-xs text-muted-foreground">
          {resultCount} / {evidenceCount} 条
        </span>
        <ExportButton label="JSON" onClick={onExportJSON} />
        <ExportButton label="CSV" onClick={onExportCSV} />
      </div>
    </div>
  );
}

interface EvidenceModuleButtonProps {
  active: boolean;
  label: string;
  module: string;
  onToggle: (module: string) => void;
}

function EvidenceModuleButton({ active, label, module, onToggle }: EvidenceModuleButtonProps) {
  return (
    <button
      type="button"
      onClick={() => onToggle(module)}
      className={cn(
        "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-all",
        active
          ? "border-indigo-200 bg-indigo-100 text-indigo-700 shadow-sm"
          : "border-slate-200 bg-white/80 text-slate-500 hover:border-indigo-200 hover:text-indigo-700",
      )}
    >
      {label}
    </button>
  );
}

interface ExportButtonProps {
  label: string;
  onClick: () => void;
}

function ExportButton({ label, onClick }: ExportButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-1 rounded-md border border-border bg-background px-2.5 py-1 text-[11px] font-medium text-foreground shadow-sm transition-colors hover:bg-accent"
    >
      <Download className="h-3 w-3" /> {label}
    </button>
  );
}

interface EvidenceStatusMessageProps {
  error: string | null;
  loading: boolean;
}

export function EvidenceStatusMessage({ error, loading }: EvidenceStatusMessageProps) {
  if (loading) {
    return (
      <div className="mb-4 rounded-2xl border border-indigo-100 bg-white/80 px-4 py-3 text-xs font-medium text-slate-500 shadow-sm">
        正在聚合跨模块证据...
      </div>
    );
  }

  if (error) {
    return (
      <div className="mb-4 rounded-2xl border border-amber-200 bg-amber-50/80 px-4 py-3 text-xs text-amber-700 shadow-sm">
        {error}
      </div>
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
        <span
          key={tag}
          className="rounded-full border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] text-slate-600"
        >
          {tag}
        </span>
      ))}
      {tags.length > 3 && <span className="text-[10px] text-slate-400">+{tags.length - 3}</span>}
    </div>
  );
}

interface EvidenceCaveatsProps {
  records: UnifiedEvidenceRecord[];
}

export function EvidenceCaveats({ records }: EvidenceCaveatsProps) {
  const caveats = collectEvidenceCaveats(records);
  if (caveats.length === 0) return null;

  return (
    <div className="mt-4 rounded-2xl border border-amber-100 bg-amber-50/60 px-4 py-3 text-[11px] text-amber-700">
      <div className="mb-1 font-semibold">证据使用提示</div>
      <ul className="list-inside list-disc space-y-0.5">
        {caveats.map((caveat) => (
          <li key={caveat}>{caveat}</li>
        ))}
      </ul>
    </div>
  );
}
