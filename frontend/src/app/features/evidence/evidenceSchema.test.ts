import { describe, expect, it } from "vitest";
import { confidenceLabel, confidenceLabelText, fromAPTEvidence, fromC2Indicator, fromThreatHit } from "./evidenceSchema";

describe("evidenceSchema", () => {
  it("normalizes confidence labels and labels text", () => {
    expect(confidenceLabel(88)).toBe("high");
    expect(confidenceLabel(60)).toBe("medium");
    expect(confidenceLabel(20)).toBe("low");
    expect(confidenceLabel()).toBe("unknown");
    expect(confidenceLabelText("medium")).toBe("中置信");
  });

  it("converts APT evidence into unified evidence with caveats", () => {
    const record = fromAPTEvidence({
      packetId: 42,
      actorId: "silver-fox",
      actorName: "Silver Fox / 银狐",
      sourceModule: "c2-analysis",
      family: "cs",
      evidenceType: "c2-indicator",
      evidenceValue: "c2.example.test",
      confidence: 64,
      source: "10.0.0.5:50100",
      destination: "10.0.0.9:443",
      sampleFamily: "ValleyRAT",
      transportTraits: ["https-c2"],
      scoreFactors: [{ name: "missing-object", weight: 0, direction: "missing", summary: "缺失对象证据" }],
      summary: "C2 技术证据关联 Silver Fox 候选",
    });

    expect(record.module).toBe("c2-analysis");
    expect(record.confidenceLabel).toBe("medium");
    expect(record.tags).toContain("ValleyRAT");
    expect(record.tags).toContain("missing:missing-object");
    expect(record.caveats.join(" ")).toContain("中置信");
    expect(record.caveats.join(" ")).toContain("缺失对象证据");
  });

  it("converts C2 indicators and threat hits without claiming attribution", () => {
    const c2 = fromC2Indicator({
      packetId: 7,
      family: "vshell",
      indicatorType: "websocket-handshake",
      indicatorValue: "Upgrade: websocket",
      confidence: 82,
      summary: "VShell WebSocket 握手",
      actorHints: ["silver-fox"],
    });
    const threat = fromThreatHit({
      id: 1,
      packetId: 9,
      category: "yara",
      rule: "SuspiciousWebShell",
      level: "high",
      preview: "<?php eval",
      match: "eval",
    });

    expect(c2.module).toBe("c2-analysis");
    expect(c2.confidenceLabel).toBe("high");
    expect(c2.tags).toContain("actor:silver-fox");
    expect(threat.module).toBe("threat-hunting");
    expect(threat.severity).toBe("high");
    expect(threat.caveats[0]).toContain("规则命中");
  });
});
