import { useCallback, useEffect, useMemo, useState } from "react";
import { downloadText } from "../../utils/browserFile";
import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";
import { buildEvidenceInvestigationReport } from "./evidenceInvestigationReport";
import {
  EVIDENCE_VISIBLE_PAGE_SIZE,
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
  const [visibleLimit, setVisibleLimit] = useState(EVIDENCE_VISIBLE_PAGE_SIZE);

  useEffect(() => {
    setVisibleLimit(EVIDENCE_VISIBLE_PAGE_SIZE);
  }, [query, severityFilter, facets, records]);

  const visibleRecords = useMemo(() => sorted.slice(0, visibleLimit), [sorted, visibleLimit]);
  const hasMoreVisibleRecords = visibleRecords.length < sorted.length;
  const severityCounts = useMemo(() => countEvidenceSeverity(records), [records]);
  const report = useMemo(() => buildEvidenceInvestigationReport(sorted), [sorted]);
  const facetGroups = useMemo(() => buildEvidenceFacetGroups(records), [records]);
  const summaryMetrics = useMemo(() => buildEvidenceSummaryMetrics(records, sorted), [records, sorted]);
  const selectedRecord = useMemo(
    () => selectEvidenceRecord(visibleRecords, selectedRecordId),
    [selectedRecordId, visibleRecords],
  );
  const effectiveSelectedRecordId = selectedRecord?.id ?? null;
  const showNextVisibleRecords = useCallback(() => {
    setVisibleLimit((current) => Math.min(current + EVIDENCE_VISIBLE_PAGE_SIZE, sorted.length));
  }, [sorted.length]);

  return {
    sorted,
    visibleRecords,
    visibleLimit,
    hasMoreVisibleRecords,
    severityCounts,
    report,
    facetGroups,
    summaryMetrics,
    selectedRecord,
    effectiveSelectedRecordId,
    showNextVisibleRecords,
    exportJSON: () =>
      downloadText("evidence-export.json", JSON.stringify(sorted, null, 2), "application/json;charset=utf-8"),
    exportCSV: () => downloadText("evidence-export.csv", buildEvidenceCsv(sorted), "text/csv;charset=utf-8"),
  };
}
