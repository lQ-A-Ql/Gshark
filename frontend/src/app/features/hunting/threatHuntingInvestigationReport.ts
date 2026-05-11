import type { InvestigationReport, ThreatHit } from "../../core/types";

export function buildThreatHuntingInvestigationReport(hits: ThreatHit[]): InvestigationReport {
  const report: InvestigationReport = {
    summary: [],
    evidence: [],
    details: [],
    recommendations: [],
  };

  const ctf = hits.filter((hit) => hit.category === "CTF").length;
  const owasp = hits.filter((hit) => hit.category === "OWASP").length;
  const anomaly = hits.filter((hit) => hit.category === "Anomaly").length;
  report.summary.push(
    { title: "狩猎命中", summary: `共 ${hits.length} 条命中`, tags: ["hunting", "summary"] },
    { title: "类别分布", summary: `CTF ${ctf} / OWASP ${owasp} / Anomaly ${anomaly}`, tags: ["hunting", "category"] },
  );

  for (const hit of hits.slice(0, 8)) {
    report.evidence.push({
      title: `${hit.rule} (${hit.category})`,
      summary: `${hit.preview || "--"} / match=${hit.match || "--"}`,
      severity: hit.level,
      packetId: hit.packetId > 0 ? hit.packetId : undefined,
      tags: ["hunting", hit.category.toLowerCase()],
    });
  }

  for (const hit of hits.slice(0, 6)) {
    report.details.push({
      title: hit.rule,
      summary: `类别 ${hit.category} / 级别 ${hit.level} / 预览 ${hit.preview || "--"}`,
      packetId: hit.packetId > 0 ? hit.packetId : undefined,
      tags: ["hunting", "detail"],
    });
  }

  if (hits.some((hit) => hit.level === "critical" || hit.level === "high")) {
    report.recommendations.push("优先定位高危命中对应数据包，并打开关联流确认上下文、载荷和前后响应。");
  }
  if (anomaly > 0) {
    report.recommendations.push("异常类命中建议结合同源地址、状态码聚集和时序关系复核是否属于扫描或误报基线。");
  }
  if (hits.length === 0) {
    report.recommendations.push("当前未形成狩猎命中，可调整 prefix、YARA 规则和超时，再结合对象/流量模块交叉复核。");
  }

  return report;
}
