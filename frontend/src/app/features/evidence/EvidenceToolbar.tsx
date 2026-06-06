import { Filter, Search } from "lucide-react";
import { cn } from "../../components/ui/utils";
import { EVIDENCE_MODULE_OPTIONS } from "./evidencePanelRules";
import { EvidenceExportButton } from "./EvidenceExportButton";

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
    <div className="space-y-3">
      <div className="meow-tile-toolbar flex flex-wrap items-center gap-2.5 px-3 py-2.5">
        <div className="meow-field flex min-w-[260px] flex-1 items-center gap-2 px-2 py-1">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input
            value={query}
            onChange={(event) => onQueryChange(event.target.value)}
            placeholder="搜索摘要、IOC、规则、主机、URI、标签..."
            className="w-full border-none bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground">{resultCount} / {evidenceCount} 条</span>
          <EvidenceExportButton label="JSON" onClick={onExportJSON} />
          <EvidenceExportButton label="CSV" onClick={onExportCSV} />
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
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
    </div>
  );
}

function EvidenceModuleButton({
  active,
  label,
  module,
  onToggle,
}: {
  active: boolean;
  label: string;
  module: string;
  onToggle: (module: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onToggle(module)}
      className={cn(
        "meow-control px-2.5 py-1 text-[11px] font-medium transition-all",
        active ? "border-indigo-200 bg-indigo-100 text-indigo-700" : "text-slate-500 hover:text-indigo-700",
      )}
    >
      {label}
    </button>
  );
}
