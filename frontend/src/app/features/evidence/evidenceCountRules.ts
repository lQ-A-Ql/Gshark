import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";
import {
  EVIDENCE_CONFIDENCE_LABELS,
  type EvidenceFacetGroups,
  type EvidenceFacetOption,
  type EvidenceSummaryMetrics,
} from "./evidenceConstants";
import { confidenceLabel } from "./evidenceRecordLabels";

export function countEvidenceSeverity(records: UnifiedEvidenceRecord[]) {
  const counts: Record<EvidenceSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of records) {
    counts[item.severity] = (counts[item.severity] ?? 0) + 1;
  }
  return counts;
}

export function collectEvidenceCaveats(records: UnifiedEvidenceRecord[]) {
  return Array.from(new Set(records.flatMap((item) => item.caveats))).slice(0, 5);
}

export function buildEvidenceFacetGroups(records: UnifiedEvidenceRecord[]): EvidenceFacetGroups {
  return {
    sourceTypes: buildFacetOptions(records, (item) => item.sourceType),
    features: buildFacetOptions(records, (item) => item.feature),
    entities: buildFacetOptions(records, (item) => item.entityType),
    confidenceLabels: EVIDENCE_CONFIDENCE_LABELS.map((value) => ({
      value,
      label: confidenceLabel(value),
      count: records.filter((item) => (item.confidenceLabel || "unknown") === value).length,
    })).filter((item) => item.count > 0),
  };
}

export function buildEvidenceSummaryMetrics(
  records: UnifiedEvidenceRecord[],
  visibleRecords: UnifiedEvidenceRecord[],
): EvidenceSummaryMetrics {
  return {
    totalRecords: records.length,
    visibleRecords: visibleRecords.length,
    moduleCount: new Set(records.map((item) => item.module)).size,
    criticalHighCount: records.filter((item) => item.severity === "critical" || item.severity === "high").length,
    mappedPacketCount: records.filter((item) => typeof item.packetId === "number" && item.packetId > 0).length,
    mappedStreamCount: records.filter((item) => typeof item.streamId === "number" && item.streamId > 0).length,
  };
}

function buildFacetOptions(
  records: UnifiedEvidenceRecord[],
  pickValue: (record: UnifiedEvidenceRecord) => string | undefined,
): EvidenceFacetOption[] {
  const counts = new Map<string, number>();
  for (const record of records) {
    const value = pickValue(record)?.trim();
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, label: value, count }))
    .sort((a, b) => (b.count !== a.count ? b.count - a.count : a.label.localeCompare(b.label)));
}
