import type { UnifiedEvidenceRecord } from "./evidenceSchema";

export function buildEvidenceCsv(records: UnifiedEvidenceRecord[]) {
  const headers = [
    "module", "severity", "confidence", "sourceType", "displayName", "family", "version", "protocol",
    "ruleId", "ruleName", "playbookId", "playbookName", "iocType", "iocValue", "ja3Hash", "ja3sHash",
    "metadata", "summary", "packetId", "tags",
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
