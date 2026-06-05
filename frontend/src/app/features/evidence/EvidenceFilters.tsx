import { Download, Filter, Search } from "lucide-react";
import { StatusHint, SurfacePanel } from "../../components/DesignSystem";
import { cn } from "../../components/ui/utils";
import type { EvidenceSeverity } from "./evidenceSchema";
import {
  EVIDENCE_MODULE_OPTIONS,
  EVIDENCE_SEVERITIES,
  type EvidenceFacetGroups,
  type EvidenceFacetState,
  confidenceLabel,
  severityActiveStyle,
  severityLabel,
} from "./evidencePanelRules";

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
    <div className="flex flex-wrap gap-2">
      {EVIDENCE_SEVERITIES.map((severity) => (
        <button
          key={severity}
          type="button"
          onClick={() => onSeverityFilterChange(severityFilter === severity ? "all" : severity)}
          className={cn(
            "meow-control px-3 py-1 text-[11px] font-medium transition-all",
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
          <span className="text-xs text-muted-foreground">
            {resultCount} / {evidenceCount} 条
          </span>
          <ExportButton label="JSON" onClick={onExportJSON} />
          <ExportButton label="CSV" onClick={onExportCSV} />
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

interface EvidenceFacetSidebarProps {
  facets: EvidenceFacetState;
  facetGroups: EvidenceFacetGroups;
  onToggleFacet: (group: keyof EvidenceFacetState, value: string) => void;
  onResetFacets: () => void;
}

export function EvidenceFacetSidebar({
  facets,
  facetGroups,
  onToggleFacet,
  onResetFacets,
}: EvidenceFacetSidebarProps) {
  return (
    <SurfacePanel
      title="调查切面"
      description="按现有证据字段组合筛选结果，未提供的字段不会伪造补全。"
      variant="section"
      actions={
        <button type="button" className="meow-control px-3 py-1 text-[11px] text-slate-600" onClick={onResetFacets}>
          清空切面
        </button>
      }
      className="h-full"
      bodyClassName="space-y-3"
    >
      <FacetGroup
        title="来源类型"
        options={facetGroups.sourceTypes}
        selected={facets.sourceTypes}
        onToggle={(value) => onToggleFacet("sourceTypes", value)}
      />
      <FacetGroup
        title="特征"
        options={facetGroups.features}
        selected={facets.features}
        onToggle={(value) => onToggleFacet("features", value)}
      />
      <FacetGroup
        title="实体"
        options={facetGroups.entities}
        selected={facets.entities}
        onToggle={(value) => onToggleFacet("entities", value)}
      />
      <FacetGroup
        title="置信标签"
        options={facetGroups.confidenceLabels.map((item) => ({ ...item, label: confidenceLabel(item.value) }))}
        selected={facets.confidenceLabels}
        onToggle={(value) => onToggleFacet("confidenceLabels", value)}
      />
      {facetGroups.features.length === 0 && facetGroups.entities.length === 0 ? (
        <StatusHint tone="slate">当前证据未提供更多 feature/entity 字段，侧栏仅展示已支持的切面。</StatusHint>
      ) : null}
    </SurfacePanel>
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
        "meow-control px-2.5 py-1 text-[11px] font-medium transition-all",
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
      className="meow-control flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-foreground transition-colors"
    >
      <Download className="h-3 w-3" /> {label}
    </button>
  );
}

function FacetGroup({
  title,
  options,
  selected,
  onToggle,
}: {
  title: string;
  options: { value: string; label: string; count: number }[];
  selected: string[];
  onToggle: (value: string) => void;
}) {
  if (options.length === 0) return null;

  return (
    <div className="space-y-2">
      <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">{title}</div>
      <div className="space-y-1.5">
        {options.map((option) => {
          const active = selected.includes(option.value);
          return (
            <button
              key={`${title}-${option.value}`}
              type="button"
              onClick={() => onToggle(option.value)}
              className={cn(
                "meow-soft-fill flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-xs transition-colors",
                active ? "border-indigo-200 bg-indigo-50 text-indigo-700" : "text-slate-600 hover:text-slate-900",
              )}
            >
              <span className="min-w-0 truncate">{option.label}</span>
              <span className="shrink-0 text-[10px] text-slate-400">{option.count}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
