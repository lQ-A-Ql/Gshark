import type { UnifiedEvidenceRecord } from "./evidenceSchema";

export function selectEvidenceRecord(records: UnifiedEvidenceRecord[], selectedId: string | null): UnifiedEvidenceRecord | null {
  if (records.length === 0) return null;
  if (!selectedId) return records[0] ?? null;
  return records.find((item) => item.id === selectedId) ?? records[0] ?? null;
}

export function missingEvidenceContext(record: UnifiedEvidenceRecord | null): string[] {
  if (!record) return [];
  const missing: string[] = [];
  if (!record.packetId) missing.push("未绑定原始包号");
  if (!record.streamId) missing.push("未绑定关联流 ID");
  if (!record.feature && !record.entityType && !record.sourceType) missing.push("特征分类字段未提供");
  if (!record.ruleId && !record.playbookId && !record.iocValue && !record.ja3Hash && !record.ja3sHash) {
    missing.push("检测上下文字段较少");
  }
  return missing;
}

export function evidenceFieldValue(record: UnifiedEvidenceRecord, field: keyof UnifiedEvidenceRecord): string {
  const value = record[field];
  if (value == null || value === "") return "--";
  if (Array.isArray(value)) return value.length > 0 ? value.join(", ") : "--";
  return String(value);
}

export function evidenceLocationValue(record: UnifiedEvidenceRecord): string {
  const hostUri = [record.host, record.uri].filter(Boolean).join("");
  if (hostUri) return hostUri;
  const sourceDestination = [record.source, record.destination].filter(Boolean).join(" → ");
  if (sourceDestination) return sourceDestination;
  return "--";
}

export function hasValidPacketId(packetId: number | null | undefined): boolean {
  return Number.isFinite(Number(packetId)) && Number(packetId) > 0;
}

export function hasValidStreamId(streamId: number | null | undefined): boolean {
  return Number.isFinite(Number(streamId)) && Number(streamId) > 0;
}
