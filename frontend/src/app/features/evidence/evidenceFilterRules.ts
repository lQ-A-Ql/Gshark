import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";
import type { EvidenceFacetState } from "./evidenceConstants";
import { searchableEvidenceFields } from "./evidenceRecordLabels";

export function filterEvidenceRecords(
  records: UnifiedEvidenceRecord[],
  query: string,
  severityFilter: EvidenceSeverity | "all",
  facets?: Partial<EvidenceFacetState>,
) {
  return records.filter((item) => {
    const matchesSeverity = severityFilter === "all" || item.severity === severityFilter;
    const matchesQuery = !query.trim() || matchesSearch(item, query);
    const matchesSourceType = matchesFacet(item.sourceType, facets?.sourceTypes);
    const matchesFeature = matchesFacet(item.feature, facets?.features);
    const matchesEntity = matchesFacet(item.entityType, facets?.entities);
    const matchesConfidence = matchesFacet(item.confidenceLabel, facets?.confidenceLabels);
    return matchesSeverity && matchesQuery && matchesSourceType && matchesFeature && matchesEntity && matchesConfidence;
  });
}

export function matchesSearch(item: UnifiedEvidenceRecord, query: string): boolean {
  const lower = query.toLowerCase();
  return searchableEvidenceFields(item).some((value) => value.toLowerCase().includes(lower));
}

function matchesFacet(value: string | undefined, selected: string[] | undefined): boolean {
  if (!selected || selected.length === 0) return true;
  if (!value) return false;
  return selected.includes(value);
}
