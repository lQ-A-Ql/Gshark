import type { EvidenceModule, EvidenceSeverity, UnifiedEvidenceRecord } from "../../core/types";
import { normalizeTrafficTimelineBuckets } from "./trafficTimeline";
import type { TimelinePoint } from "./TrafficAreaChart";

export interface TrafficTimelineEvidenceEvent {
  id: string;
  label: string;
  title: string;
  severity: EvidenceSeverity;
  module: EvidenceModule;
  sourceType?: string;
  ruleName?: string;
  packetId?: number;
  streamId?: number;
  isYara: boolean;
  isCommunityYara: boolean;
}

export interface TrafficTimelineEvidenceSummary {
  events: TrafficTimelineEvidenceEvent[];
  unplacedRecords: UnifiedEvidenceRecord[];
  evidenceCount: number;
  yaraCount: number;
  communityYaraCount: number;
}

export function buildTrafficTimelineEvidence(
  timeline: TimelinePoint[],
  records: UnifiedEvidenceRecord[],
): TrafficTimelineEvidenceSummary {
  const normalizedTimeline = normalizeTrafficTimelineBuckets(timeline);
  const labels = new Set(normalizedTimeline.map((point) => point.label));
  const events: TrafficTimelineEvidenceEvent[] = [];
  const unplacedRecords: UnifiedEvidenceRecord[] = [];

  for (const record of records) {
    const label = timelineLabelForEvidence(record, labels);
    if (!label) {
      unplacedRecords.push(record);
      continue;
    }
    const isYara = evidenceIsYara(record);
    const isCommunityYara = isYara && evidenceIsCommunityYara(record);
    events.push({
      id: record.id,
      label,
      title: record.summary || record.ruleName || record.value || record.id,
      severity: record.severity,
      module: record.module,
      sourceType: record.sourceType,
      ruleName: record.ruleName ?? record.summary,
      packetId: record.packetId,
      streamId: record.streamId,
      isYara,
      isCommunityYara,
    });
  }

  const yaraCount = records.filter(evidenceIsYara).length;
  const communityYaraCount = records.filter((record) => evidenceIsYara(record) && evidenceIsCommunityYara(record)).length;
  return {
    events,
    unplacedRecords,
    evidenceCount: records.length,
    yaraCount,
    communityYaraCount,
  };
}

export function evidenceEventsInSelection(
  events: TrafficTimelineEvidenceEvent[],
  labels: string[],
  startLabel: string,
  endLabel: string,
) {
  const startIndex = labels.indexOf(startLabel);
  const endIndex = labels.indexOf(endLabel);
  if (startIndex < 0 || endIndex < 0) return [];
  const minIndex = Math.min(startIndex, endIndex);
  const maxIndex = Math.max(startIndex, endIndex);
  const selectedLabels = new Set(labels.slice(minIndex, maxIndex + 1));
  return events.filter((event) => selectedLabels.has(event.label));
}

function timelineLabelForEvidence(record: UnifiedEvidenceRecord, timelineLabels: Set<string>) {
  const raw = metadataString(record, "time") ?? metadataString(record, "timestamp") ?? metadataString(record, "ts");
  if (!raw) return null;
  const [normalized] = normalizeTrafficTimelineBuckets([{ label: raw, count: 1 }]);
  if (!normalized || !timelineLabels.has(normalized.label)) return null;
  return normalized.label;
}

function metadataString(record: UnifiedEvidenceRecord, key: string) {
  const value = record.metadata?.[key];
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }
  return null;
}

export function evidenceIsYara(record: UnifiedEvidenceRecord) {
  const haystack = [record.module, record.sourceModule, record.sourceType, record.ruleName, record.summary, record.value, ...record.tags]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes("yara") || Boolean(record.metadata?.rule_origin || record.metadata?.rule_source || record.metadata?.rule_pack);
}

export function evidenceIsCommunityYara(record: UnifiedEvidenceRecord) {
  const metadata = record.metadata ?? {};
  const communityFlag = metadata.community_rule;
  if (communityFlag === true || String(communityFlag).toLowerCase() === "true") return true;
  const haystack = [metadata.rule_origin, metadata.rule_source, metadata.rule_pack]
    .filter((value): value is string | number | boolean => typeof value === "string" || typeof value === "number" || typeof value === "boolean")
    .join(" ")
    .toLowerCase();
  return haystack.includes("community") || haystack.includes("neo23x0") || haystack.includes("signature-base");
}
