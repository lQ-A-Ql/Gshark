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
] as const;

export const EVIDENCE_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function filterEvidenceRecords(
  records: UnifiedEvidenceRecord[],
  query: string,
  severityFilter: EvidenceSeverity | "all",
) {
  return records.filter((item) => {
    const matchesSeverity = severityFilter === "all" || item.severity === severityFilter;
    const matchesQuery = !query.trim() || matchesSearch(item, query);
    return matchesSeverity && matchesQuery;
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
  const headers = ["module", "severity", "confidence", "sourceType", "summary", "packetId", "tags"];
  const rows = records.map((item) => [
    item.module,
    item.severity,
    String(item.confidence ?? ""),
    item.sourceType,
    `"${(item.summary || "").replace(/"/g, '""')}"`,
    String(item.packetId ?? ""),
    item.tags.join("; "),
  ]);
  return [headers.join(","), ...rows.map((row) => row.join(","))].join("\n");
}

export function collectEvidenceCaveats(records: UnifiedEvidenceRecord[]) {
  return Array.from(new Set(records.flatMap((item) => item.caveats))).slice(0, 5);
}

export function matchesSearch(item: UnifiedEvidenceRecord, query: string): boolean {
  const lower = query.toLowerCase();
  return (
    item.summary.toLowerCase().includes(lower) ||
    (item.value ?? "").toLowerCase().includes(lower) ||
    item.sourceType.toLowerCase().includes(lower) ||
    item.tags.some((tag) => tag.toLowerCase().includes(lower)) ||
    (item.host ?? "").toLowerCase().includes(lower) ||
    (item.uri ?? "").toLowerCase().includes(lower)
  );
}

export function severityLabel(severity: EvidenceSeverity): string {
  return { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" }[severity] ?? severity;
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
      misc: "MISC",
      stream: "流",
    }[module] ?? module
  );
}
