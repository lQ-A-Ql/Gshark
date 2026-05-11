import { describe, expect, it } from "vitest";

import { buildObjectInvestigationReport } from "./objectInvestigationReport";

describe("buildObjectInvestigationReport", () => {
  it("surfaces executable and archive objects as actionable evidence", () => {
    const report = buildObjectInvestigationReport([
      {
        id: 1,
        packetId: 11,
        name: "payload.exe",
        sizeBytes: 2048,
        mime: "application/x-dosexec",
        magic: "PE/DOS MZ",
        source: "HTTP",
      },
      {
        id: 2,
        packetId: 12,
        name: "docs.zip",
        sizeBytes: 4096,
        mime: "application/zip",
        magic: "ZIP archive",
        source: "FTP",
      },
    ]);

    expect(report.summary[0]).toMatchObject({ title: "对象概览" });
    expect(report.evidence[0]).toMatchObject({ title: "payload.exe 为可执行对象", severity: "high", packetId: 11 });
    expect(report.evidence[1]).toMatchObject({ title: "docs.zip 为高价值文件对象", severity: "medium", packetId: 12 });
    expect(report.recommendations.length).toBeGreaterThan(0);
  });
});
