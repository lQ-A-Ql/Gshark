import { describe, expect, it } from "vitest";

import { buildThreatHuntingInvestigationReport } from "./threatHuntingInvestigationReport";

describe("buildThreatHuntingInvestigationReport", () => {
  it("turns hits into shared summary, evidence, details, and recommendations", () => {
    const report = buildThreatHuntingInvestigationReport([
      {
        id: 1,
        packetId: 99,
        category: "CTF",
        rule: "Flag 嗅探",
        level: "high",
        preview: "flag{demo}",
        match: "flag{",
      },
      {
        id: 2,
        packetId: 0,
        category: "Anomaly",
        rule: "异常扫描行为",
        level: "medium",
        preview: "短时间 403/404 激增",
        match: "10.0.0.2",
      },
    ]);

    expect(report.summary[0]).toMatchObject({ title: "狩猎命中", summary: "共 2 条命中" });
    expect(report.evidence[0]).toMatchObject({ title: "Flag 嗅探 (CTF)", severity: "high", packetId: 99 });
    expect(report.recommendations.some((item) => item.includes("高危命中"))).toBe(true);
  });
});
