import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { SEVERITY_ORDER } from "./evidenceConstants";

export function sortEvidenceRecords(records: UnifiedEvidenceRecord[]) {
  return [...records].sort((a, b) => {
    const severityA = SEVERITY_ORDER[a.severity] ?? 5;
    const severityB = SEVERITY_ORDER[b.severity] ?? 5;
    if (severityA !== severityB) return severityA - severityB;
    return (b.confidence ?? 0) - (a.confidence ?? 0);
  });
}
