import type { AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";

export const EVIDENCE_MODULE_OPTIONS = [
  { value: "hunting", label: "威胁狩猎" },
  { value: "c2", label: "C2 分析" },
  { value: "apt", label: "APT 画像" },
  { value: "industrial", label: "工控分析" },
  { value: "object", label: "对象导出" },
  { value: "vehicle", label: "车机分析" },
  { value: "usb", label: "USB 分析" },
  { value: "media", label: "媒体分析" },
  { value: "misc", label: "MISC 分析" },
] as const;

export const EVIDENCE_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const EVIDENCE_CONFIDENCE_LABELS = ["high", "medium", "low", "unknown"] as const;

export const EVIDENCE_VISIBLE_PAGE_SIZE = 200;

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface EvidenceFacetState {
  sourceTypes: string[];
  features: string[];
  entities: string[];
  confidenceLabels: string[];
}

export interface EvidenceFacetOption {
  value: string;
  label: string;
  count: number;
}

export interface EvidenceFacetGroups {
  sourceTypes: EvidenceFacetOption[];
  features: EvidenceFacetOption[];
  entities: EvidenceFacetOption[];
  confidenceLabels: EvidenceFacetOption[];
}

export interface EvidenceSummaryMetrics {
  totalRecords: number;
  visibleRecords: number;
  moduleCount: number;
  criticalHighCount: number;
  mappedPacketCount: number;
  mappedStreamCount: number;
}

export const VERSION_UNAVAILABLE_LABEL = "未提供";
export const IOC_API_UNAVAILABLE_LABEL = "IOC API unavailable";
const CHINA_CHOPPER_LABEL = "菜刀 / China Chopper";

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

export function sortEvidenceRecords(records: UnifiedEvidenceRecord[]) {
  return [...records].sort((a, b) => {
    const severityA = SEVERITY_ORDER[a.severity] ?? 5;
    const severityB = SEVERITY_ORDER[b.severity] ?? 5;
    if (severityA !== severityB) return severityA - severityB;
    return (b.confidence ?? 0) - (a.confidence ?? 0);
  });
}

export function countEvidenceSeverity(records: UnifiedEvidenceRecord[]) {
  const counts: Record<EvidenceSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of records) {
    counts[item.severity] = (counts[item.severity] ?? 0) + 1;
  }
  return counts;
}

export function buildEvidenceCsv(records: UnifiedEvidenceRecord[]) {
  const headers = [
    "module",
    "severity",
    "confidence",
    "sourceType",
    "displayName",
    "family",
    "version",
    "protocol",
    "ruleId",
    "ruleName",
    "playbookId",
    "playbookName",
    "iocType",
    "iocValue",
    "ja3Hash",
    "ja3sHash",
    "metadata",
    "summary",
    "packetId",
    "tags",
  ];
  const rows = records.map((item) => [
    item.module,
    item.severity,
    String(item.confidence ?? ""),
    item.sourceType,
    csvCell(item.displayName),
    csvCell(item.family),
    csvCell(item.version),
    csvCell(item.protocol),
    csvCell(item.ruleId),
    csvCell(item.ruleName),
    csvCell(item.playbookId),
    csvCell(item.playbookName),
    csvCell(item.iocType),
    csvCell(item.iocValue),
    csvCell(item.ja3Hash),
    csvCell(item.ja3sHash),
    csvCell(item.metadata ? JSON.stringify(item.metadata) : undefined),
    `"${(item.summary || "").replace(/"/g, '""')}"`,
    String(item.packetId ?? ""),
    csvCell(item.tags.join("; ")),
  ]);
  return [headers.join(","), ...rows.map((row) => row.join(","))].join("\n");
}

function csvCell(value: string | undefined): string {
  const text = value ?? "";
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
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

export function evidenceSourceTypeLabel(sourceType: string | undefined): string {
  return normalizeEvidenceKeyword(sourceType);
}

export function evidenceFamilyLabel(record: UnifiedEvidenceRecord): string | undefined {
  if (isChinaChopperRecord(record)) return CHINA_CHOPPER_LABEL;
  if (record.family?.trim()) return normalizeEvidenceKeyword(record.family);
  if (isWebShellRecord(record)) return VERSION_UNAVAILABLE_LABEL;
  return undefined;
}

export function evidenceVersionLabel(record: UnifiedEvidenceRecord): string | undefined {
  if (record.version?.trim()) return record.version;
  if (isWebShellRecord(record)) return VERSION_UNAVAILABLE_LABEL;
  return undefined;
}

export function evidenceProtocolLabel(record: UnifiedEvidenceRecord): string | undefined {
  if (record.protocol?.trim()) return normalizeEvidenceKeyword(record.protocol);
  if (isDnp3Record(record)) return "DNP3";
  return undefined;
}

export function evidenceIocLabel(record: UnifiedEvidenceRecord): string | undefined {
  const formatted = [record.iocType, record.iocValue].filter(Boolean).join(": ");
  if (formatted) return formatted;
  if (normalizeEvidenceValue(record.sourceType) === "ioc") return IOC_API_UNAVAILABLE_LABEL;
  return undefined;
}

export function evidencePlaybookLabel(record: UnifiedEvidenceRecord): string | undefined {
  const formatted = [record.playbookId, record.playbookName].filter(Boolean).join(" / ");
  if (formatted) return formatted;
  if (normalizeEvidenceValue(record.sourceType) === "playbook") return "Playbook 未提供";
  return undefined;
}

export function evidenceRuleLabel(record: UnifiedEvidenceRecord): string | undefined {
  const formatted = [record.ruleId, record.ruleName].filter(Boolean).join(" / ");
  if (formatted) return formatted;
  if (normalizeEvidenceValue(record.sourceType) === "rule") return "Rule 未提供";
  return undefined;
}

export function matchesSearch(item: UnifiedEvidenceRecord, query: string): boolean {
  const lower = query.toLowerCase();
  return searchableEvidenceFields(item).some((value) => value.toLowerCase().includes(lower));
}

function searchableEvidenceFields(item: UnifiedEvidenceRecord): string[] {
  return [
    item.summary,
    item.value,
    item.sourceType,
    item.host,
    item.uri,
    item.family,
    item.feature,
    item.entityType,
    item.protocol,
    item.version,
    item.displayName,
    item.ruleId,
    item.ruleName,
    item.playbookId,
    item.playbookName,
    item.iocType,
    item.iocValue,
    item.ja3Hash,
    item.ja3sHash,
    item.actorId,
    item.actorName,
    item.sourceModule,
    item.source,
    item.destination,
    evidenceSourceTypeLabel(item.sourceType),
    evidenceFamilyLabel(item),
    evidenceProtocolLabel(item),
    evidenceVersionLabel(item),
    evidenceIocLabel(item),
    evidencePlaybookLabel(item),
    evidenceRuleLabel(item),
    ...item.tags,
    ...Object.values(item.metadata ?? {})
      .flatMap((value) => (Array.isArray(value) ? value : [value]))
      .map(String),
  ].filter((value): value is string => Boolean(value));
}

export function severityLabel(severity: EvidenceSeverity): string {
  return { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" }[severity] ?? severity;
}

export function confidenceLabel(label: string): string {
  return { high: "高", medium: "中", low: "低", unknown: "未知" }[label] ?? label;
}

export function severityTone(severity: EvidenceSeverity): AnalysisTone {
  const map: Record<string, AnalysisTone> = {
    critical: "rose",
    high: "rose",
    medium: "amber",
    low: "blue",
    info: "slate",
  };
  return map[severity] ?? "slate";
}

export function severityActiveStyle(severity: EvidenceSeverity): string {
  return (
    {
      critical: "border-rose-300 bg-rose-100 text-rose-700",
      high: "border-rose-200 bg-rose-50 text-rose-700",
      medium: "border-amber-200 bg-amber-100 text-amber-700",
      low: "border-blue-200 bg-blue-50 text-blue-700",
      info: "border-slate-300 bg-slate-100 text-slate-700",
    }[severity] ?? "border-slate-200 bg-slate-50 text-slate-600"
  );
}

export function confidenceColor(confidence: number): string {
  if (confidence >= 75) return "text-emerald-600";
  if (confidence >= 45) return "text-amber-600";
  return "text-rose-600";
}

export function moduleLabel(module: string): string {
  return (
    {
      hunting: "狩猎",
      c2: "C2",
      apt: "APT",
      industrial: "工控",
      vehicle: "车机",
      usb: "USB",
      object: "对象",
      media: "媒体",
      misc: "MISC",
      stream: "流",
    }[module] ?? module
  );
}

function matchesFacet(value: string | undefined, selected: string[] | undefined): boolean {
  if (!selected || selected.length === 0) return true;
  if (!value) return false;
  return selected.includes(value);
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

function normalizeEvidenceKeyword(value: string | undefined): string {
  if (!value?.trim()) return "";
  const normalized = normalizeEvidenceValue(value);
  if (normalized === "ja3") return "JA3";
  if (normalized === "ja3s") return "JA3S";
  if (normalized === "china_chopper") return CHINA_CHOPPER_LABEL;
  if (normalized === "webshell") return "WebShell";
  if (normalized === "dnp3") return "DNP3";
  if (normalized === "playbook") return "Playbook";
  if (normalized === "ioc") return "IOC";
  if (normalized === "rule") return "Rule";
  return value;
}

function normalizeEvidenceValue(value: string | undefined): string {
  return (value ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");
}

function isChinaChopperRecord(record: UnifiedEvidenceRecord): boolean {
  const values = [record.sourceType, record.family];
  return values.some((value) => {
    const normalized = normalizeEvidenceValue(value);
    return normalized === "china_chopper" || normalized === "caidao" || normalized === "菜刀";
  });
}

function isWebShellRecord(record: UnifiedEvidenceRecord): boolean {
  const values = [record.sourceType, record.family];
  return values.some((value) => {
    const normalized = normalizeEvidenceValue(value);
    return normalized === "webshell" || normalized === "china_chopper" || normalized === "caidao" || normalized === "菜刀";
  });
}

function isDnp3Record(record: UnifiedEvidenceRecord): boolean {
  const values = [record.sourceType, record.family, record.protocol, record.sourceModule];
  return values.some((value) => normalizeEvidenceValue(value) === "dnp3");
}
