import { cn } from "../../components/ui/utils";
import type { EvidenceSeverity } from "./evidenceSchema";
import { EVIDENCE_SEVERITIES, severityActiveStyle, severityLabel } from "./evidencePanelRules";

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
