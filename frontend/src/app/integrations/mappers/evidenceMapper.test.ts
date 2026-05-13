import { describe, expect, it } from "vitest";
import { normalizeEvidenceModule, parseEvidenceRecords } from "./evidenceMapper";

describe("evidenceMapper", () => {
  it("maps backend evidence records into the unified frontend contract", () => {
    const records = parseEvidenceRecords({
      records: [
        {
          id: "industrial:7",
          module: "industrial-analysis",
          source_module: "modbus",
          packet_id: 7,
          stream_id: 3,
          family: "modbus",
          actor_id: "actor-1",
          actor_name: "Operator",
          source_type: "control-command",
          summary: "write register",
          value: "40001",
          confidence: 80,
          severity: "high",
          source: "10.0.0.1",
          destination: "10.0.0.2",
          host: "plc.local",
          uri: "/api",
          tags: ["write", 16],
          caveats: ["review"],
        },
      ],
    });

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      id: "industrial:7",
      module: "industrial",
      sourceModule: "modbus",
      packetId: 7,
      streamId: 3,
      confidenceLabel: "high",
      severity: "high",
      tags: ["write", "16"],
      caveats: ["review"],
    });
  });

  it("normalizes known module aliases and keeps unknown input explicit", () => {
    expect(normalizeEvidenceModule("yara-threat-hunting")).toBe("hunting");
    expect(normalizeEvidenceModule("webshell-decoder")).toBe("misc");
    expect(normalizeEvidenceModule("object-file")).toBe("object");
    expect(normalizeEvidenceModule("unmapped")).toBe("unknown");
  });

  it("treats malformed wire payloads as empty or defaulted records", () => {
    expect(parseEvidenceRecords(null)).toEqual([]);
    expect(parseEvidenceRecords({ records: "bad" })).toEqual([]);

    expect(parseEvidenceRecords({ records: [null] })[0]).toMatchObject({
      id: "",
      module: "unknown",
      sourceType: "",
      summary: "",
      confidenceLabel: "unknown",
      severity: "info",
      tags: [],
      caveats: [],
    });
  });
});
