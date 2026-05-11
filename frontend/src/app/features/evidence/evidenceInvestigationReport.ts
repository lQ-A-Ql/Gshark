import type { InvestigationReport } from "../../core/types";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import { moduleLabel, severityLabel } from "./evidencePanelRules";

export function buildEvidenceInvestigationReport(records: UnifiedEvidenceRecord[]): InvestigationReport {
  const report: InvestigationReport = {
    summary: [],
    evidence: [],
    details: [],
    recommendations: [],
  };

  const modules = Array.from(new Set(records.map((item) => item.module)));
  report.summary.push(
    {
      title: "统一证据概览",
      summary: `共 ${records.length} 条证据 / 模块 ${modules.length} 个`,
      tags: ["evidence", "summary"],
    },
    {
      title: "高危分布",
      summary: `严重 ${countBySeverity(records, "critical")} / 高危 ${countBySeverity(records, "high")} / 中危 ${countBySeverity(records, "medium")}`,
      tags: ["evidence", "severity"],
    },
  );

  for (const item of sortByPriority(records).slice(0, 6)) {
    report.evidence.push({
      title: `${moduleLabel(item.module)} · ${item.summary}`,
      summary: [
        `${severityLabel(item.severity)}${item.confidence ? ` / 置信度 ${item.confidence}%` : ""}`,
        item.value,
        item.host && item.uri ? `${item.host}${item.uri}` : item.host || item.uri,
      ]
        .filter(Boolean)
        .join(" / "),
      severity: item.severity,
      packetId: item.packetId,
      streamId: item.streamId,
      tags: item.tags.slice(0, 5),
    });
  }

  for (const item of sortByPriority(records).slice(0, 6)) {
    report.details.push({
      title: `${moduleLabel(item.module)} · ${item.sourceType}`,
      summary: [item.summary, item.source, item.destination].filter(Boolean).join(" / "),
      packetId: item.packetId,
      streamId: item.streamId,
      tags: [item.module, ...(item.tags ?? []).slice(0, 3)],
    });
  }

  if (records.some((item) => item.severity === "critical" || item.severity === "high")) {
    report.recommendations.push("优先定位严重/高危证据对应数据包，并打开关联流确认前后文、载荷与会话行为。");
  }
  if (modules.length > 1) {
    report.recommendations.push("建议结合多模块证据交叉复核，同一 packet / stream / host 命中的线索应优先串成调查链。");
  }
  if (records.some((item) => item.caveats.length > 0)) {
    report.recommendations.push("存在 caveat 的证据不应单独作为结论，需结合上下文和原始流量进一步确认。");
  }
  if (records.length === 0) {
    report.recommendations.push("当前尚未聚合到主线证据，可先从威胁狩猎、协议分析和对象导出结果中回溯可复核线索。");
  }

  return report;
}

function countBySeverity(records: UnifiedEvidenceRecord[], severity: UnifiedEvidenceRecord["severity"]) {
  return records.filter((item) => item.severity === severity).length;
}

function sortByPriority(records: UnifiedEvidenceRecord[]) {
  const order: Record<UnifiedEvidenceRecord["severity"], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  return [...records].sort((a, b) => {
    const sev = (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    if (sev !== 0) return sev;
    return (b.confidence ?? 0) - (a.confidence ?? 0);
  });
}
