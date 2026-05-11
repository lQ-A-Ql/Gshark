import { useMemo } from "react";
import { downloadText } from "../../utils/browserFile";
import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";
import { buildEvidenceInvestigationReport } from "./evidenceInvestigationReport";
import {
  buildEvidenceCsv,
  countEvidenceSeverity,
  filterEvidenceRecords,
  sortEvidenceRecords,
} from "./evidencePanelRules";

export function useEvidencePanelModel(
  records: UnifiedEvidenceRecord[],
  query: string,
  severityFilter: EvidenceSeverity | "all",
) {
  const filtered = useMemo(
    () => filterEvidenceRecords(records, query, severityFilter),
    [records, query, severityFilter],
  );
  const sorted = useMemo(() => sortEvidenceRecords(filtered), [filtered]);
  const severityCounts = useMemo(() => countEvidenceSeverity(records), [records]);
  const report = useMemo(() => buildEvidenceInvestigationReport(sorted), [sorted]);

  return {
    sorted,
    severityCounts,
    report,
    exportJSON: () =>
      downloadText("evidence-export.json", JSON.stringify(sorted, null, 2), "application/json;charset=utf-8"),
    exportCSV: () => downloadText("evidence-export.csv", buildEvidenceCsv(sorted), "text/csv;charset=utf-8"),
  };
}
