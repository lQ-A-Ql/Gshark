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
    <div className="mb-3 flex flex-wrap gap-2">
      {EVIDENCE_SEVERITIES.map((severity) => (
        <button
          key={severity}
          type="button"
          onClick={() => onSeverityFilterChange(severityFilter === severity ? "all" : severity)}
          className={cn(
            "gshark-control px-3 py-1 text-[11px] font-medium transition-all",
            severityFilter === severity ? severityActiveStyle(severity) : "text-slate-600 hover:text-indigo-700",
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
    <div className="gshark-tile-toolbar flex flex-wrap items-center gap-2.5 px-3 py-2.5">
      <div className="gshark-field flex items-center gap-2 px-2 py-1">
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
        "gshark-control px-2.5 py-1 text-[11px] font-medium transition-all",
        active ? "border-indigo-200 bg-indigo-100 text-indigo-700" : "text-slate-500 hover:text-indigo-700",
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
      className="gshark-control flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-foreground transition-colors"
    >
      <Download className="h-3 w-3" /> {label}
    </button>
  );
}
