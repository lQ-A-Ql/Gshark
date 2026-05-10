import { Download, Filter, Search } from "lucide-react";
import { cn } from "../../components/ui/utils";
import type { EvidenceSeverity } from "./evidenceSchema";
import { EVIDENCE_MODULE_OPTIONS, EVIDENCE_SEVERITIES, severityActiveStyle, severityLabel } from "./evidencePanelRules";

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
