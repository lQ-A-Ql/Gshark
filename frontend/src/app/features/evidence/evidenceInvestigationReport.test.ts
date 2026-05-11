import { describe, expect, it } from "vitest";

import { buildEvidenceInvestigationReport } from "./evidenceInvestigationReport";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";

function record(overrides: Partial<UnifiedEvidenceRecord>): UnifiedEvidenceRecord {
  return {
    id: "r1",
    module: "vehicle",
    sourceType: "uds",
    summary: "UDS 负响应",
    severity: "high",
    confidence: 82,
    confidenceLabel: "high",
    tags: ["UDS", "0x27"],
    caveats: [],
    ...overrides,
  };
}

describe("buildEvidenceInvestigationReport", () => {
  it("turns unified evidence into shared report sections", () => {
    const report = buildEvidenceInvestigationReport([
      record({ packetId: 101, value: "security access denied", source: "0x0e80", destination: "0x07e0" }),
      record({
        id: "usb",
        module: "usb",
        sourceType: "mass-storage-write",
        summary: "USB 存储写入",
        severity: "medium",
        confidence: 60,
        packetId: 202,
        tags: ["USB", "write"],
        caveats: ["低置信信号，必须结合上下文人工复核。"],
      }),
    ]);

    expect(report.summary[0]).toMatchObject({ title: "统一证据概览", summary: "共 2 条证据 / 模块 2 个" });
    expect(report.evidence[0]).toMatchObject({ title: "车机 · UDS 负响应", severity: "high", packetId: 101 });
    expect(report.details[1]).toMatchObject({ title: "USB · mass-storage-write", packetId: 202 });
    expect(report.recommendations.length).toBeGreaterThan(0);
  });
});
