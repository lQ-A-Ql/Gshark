import type { InvestigationReport } from "../../core/types";

export function renderInvestigationReportText(report: InvestigationReport | undefined) {
  if (!report) return "";
  const lines: string[] = [];
  appendReportSection(lines, "摘要", report.summary);
  appendReportSection(lines, "证据", report.evidence);
  appendReportSection(lines, "明细", report.details);
  if (report.recommendations.length > 0) {
    if (lines.length > 0) lines.push("");
    lines.push("建议:");
    for (const item of report.recommendations) {
      lines.push(`- ${item}`);
    }
  }
  return lines.join("\n");
}

function appendReportSection(lines: string[], title: string, items: InvestigationReport["summary"]) {
  if (!items.length) return;
  if (lines.length > 0) lines.push("");
  lines.push(`${title}:`);
  for (const item of items) {
    const meta: string[] = [];
    if (item.severity) meta.push(`severity=${item.severity}`);
    if (item.packetId) meta.push(`packet=${item.packetId}`);
    if (item.streamId) meta.push(`stream=${item.streamId}`);
    const headline = meta.length > 0 ? `${item.title} [${meta.join(", ")}]` : item.title;
    lines.push(`- ${headline}`);
    if (item.summary) {
      lines.push(`  ${item.summary}`);
    }
    if (item.tags?.length) {
      lines.push(`  tags: ${item.tags.join(", ")}`);
    }
  }
}
