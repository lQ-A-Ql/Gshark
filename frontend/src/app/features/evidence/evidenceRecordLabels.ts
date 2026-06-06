import type { AnalysisTone } from "../../components/analysis/AnalysisPrimitives";
import type { EvidenceSeverity, UnifiedEvidenceRecord } from "./evidenceSchema";
import { CHINA_CHOPPER_LABEL, IOC_API_UNAVAILABLE_LABEL, VERSION_UNAVAILABLE_LABEL } from "./evidenceConstants";
import { normalizeEvidenceKeyword, normalizeEvidenceValue } from "./evidenceValueRules";

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

export function severityLabel(severity: EvidenceSeverity): string {
  return { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" }[severity] ?? severity;
}

export function confidenceLabel(label: string): string {
  return { high: "高", medium: "中", low: "低", unknown: "未知" }[label] ?? label;
}

export function severityTone(severity: EvidenceSeverity): AnalysisTone {
  const map: Record<string, AnalysisTone> = { critical: "rose", high: "rose", medium: "amber", low: "blue", info: "slate" };
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

export function searchableEvidenceFields(item: UnifiedEvidenceRecord): string[] {
  return [
    item.summary, item.value, item.sourceType, item.host, item.uri, item.family, item.feature, item.entityType,
    item.protocol, item.version, item.displayName, item.ruleId, item.ruleName, item.playbookId, item.playbookName,
    item.iocType, item.iocValue, item.ja3Hash, item.ja3sHash, item.actorId, item.actorName, item.sourceModule,
    item.source, item.destination, evidenceSourceTypeLabel(item.sourceType), evidenceFamilyLabel(item),
    evidenceProtocolLabel(item), evidenceVersionLabel(item), evidenceIocLabel(item), evidencePlaybookLabel(item),
    evidenceRuleLabel(item), ...item.tags,
    ...Object.values(item.metadata ?? {}).flatMap((value) => (Array.isArray(value) ? value : [value])).map(String),
  ].filter((value): value is string => Boolean(value));
}

function isChinaChopperRecord(record: UnifiedEvidenceRecord): boolean {
  return [record.sourceType, record.family].some((value) => {
    const normalized = normalizeEvidenceValue(value);
    return normalized === "china_chopper" || normalized === "caidao" || normalized === "菜刀";
  });
}

function isWebShellRecord(record: UnifiedEvidenceRecord): boolean {
  return [record.sourceType, record.family].some((value) => {
    const normalized = normalizeEvidenceValue(value);
    return normalized === "webshell" || normalized === "china_chopper" || normalized === "caidao" || normalized === "菜刀";
  });
}

function isDnp3Record(record: UnifiedEvidenceRecord): boolean {
  return [record.sourceType, record.family, record.protocol, record.sourceModule].some(
    (value) => normalizeEvidenceValue(value) === "dnp3",
  );
}
