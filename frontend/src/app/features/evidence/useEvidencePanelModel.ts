import { useMemo } from "react";
import { downloadText } from "../../utils/browserFile";
import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";
import { buildEvidenceInvestigationReport } from "./evidenceInvestigationReport";
import {
  type EvidenceFacetState,
  buildEvidenceFacetGroups,
  buildEvidenceSummaryMetrics,
  buildEvidenceCsv,
  countEvidenceSeverity,
  filterEvidenceRecords,
  selectEvidenceRecord,
  sortEvidenceRecords,
} from "./evidencePanelRules";

export function useEvidencePanelModel(
  records: UnifiedEvidenceRecord[],
  query: string,
  severityFilter: EvidenceSeverity | "all",
  facets: EvidenceFacetState,
  selectedRecordId: string | null,
) {
  const filtered = useMemo(
    () => filterEvidenceRecords(records, query, severityFilter, facets),
    [records, query, severityFilter, facets],
  );
  const sorted = useMemo(() => sortEvidenceRecords(filtered), [filtered]);
  const severityCounts = useMemo(() => countEvidenceSeverity(records), [records]);
  const report = useMemo(() => buildEvidenceInvestigationReport(sorted), [sorted]);
  const facetGroups = useMemo(() => buildEvidenceFacetGroups(records), [records]);
  const summaryMetrics = useMemo(() => buildEvidenceSummaryMetrics(records, sorted), [records, sorted]);
  const selectedRecord = useMemo(() => selectEvidenceRecord(sorted, selectedRecordId), [selectedRecordId, sorted]);

  return {
    sorted,
    severityCounts,
    report,
    facetGroups,
    summaryMetrics,
    selectedRecord,
    exportJSON: () =>
      downloadText("evidence-export.json", JSON.stringify(sorted, null, 2), "application/json;charset=utf-8"),
    exportCSV: () => downloadText("evidence-export.csv", buildEvidenceCsv(sorted), "text/csv;charset=utf-8"),
  };
}
