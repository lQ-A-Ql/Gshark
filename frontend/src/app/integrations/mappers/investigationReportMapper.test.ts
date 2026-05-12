import { describe, expect, it } from "vitest";
import { asInvestigationReport } from "./investigationReportMapper";

describe("investigationReportMapper", () => {
  it("maps report explainability metadata", () => {
    const report = asInvestigationReport({
      evidence: [
        {
          title: "USB write",
          severity: "high",
          packet_id: 21,
          rule_id: "usb.mass_storage.write.failed",
          reason: "write failed",
          confidence: 78,
          caveats: ["review status"],
          tags: ["usb"],
        },
      ],
    });

    expect(report.evidence[0]).toMatchObject({
      title: "USB write",
      severity: "high",
      packetId: 21,
      ruleId: "usb.mass_storage.write.failed",
      reason: "write failed",
      confidence: 78,
      caveats: ["review status"],
      tags: ["usb"],
    });
  });
});
