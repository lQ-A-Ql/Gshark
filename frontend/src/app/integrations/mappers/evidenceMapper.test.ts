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
          feature: "write-single-register",
          entity_type: "plc",
          protocol: "modbus",
          version: "tcp",
          display_name: "Modbus write register",
          rule_id: "ICS-001",
          rule_name: "Unsafe write",
          playbook_id: "PB-ICS",
          playbook_name: "Industrial triage",
          ioc_type: "hash",
          ioc_value: "abcd1234",
          ja3_hash: "72a589da586844d7f0818ce684948eea",
          ja3s_hash: "b742b407517bac9536a77a7b0fee28e9",
          metadata: {
            technique: "T0831",
            score: 90,
            confirmed: true,
            tags: ["ics", "write"],
            mixed: ["drop", 1],
            nested: { unsupported: true },
          },
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
      feature: "write-single-register",
      entityType: "plc",
      protocol: "modbus",
      version: "tcp",
      displayName: "Modbus write register",
      ruleId: "ICS-001",
      ruleName: "Unsafe write",
      playbookId: "PB-ICS",
      playbookName: "Industrial triage",
      iocType: "hash",
      iocValue: "abcd1234",
      ja3Hash: "72a589da586844d7f0818ce684948eea",
      ja3sHash: "b742b407517bac9536a77a7b0fee28e9",
      metadata: {
        technique: "T0831",
        score: 90,
        confirmed: true,
        tags: ["ics", "write"],
      },
      confidenceLabel: "high",
      severity: "high",
      tags: ["write", "16"],
      caveats: ["review"],
    });
  });

  it("normalizes known module aliases and keeps unknown input explicit", () => {
    expect(normalizeEvidenceModule("yara-threat-hunting")).toBe("hunting");
    expect(normalizeEvidenceModule("webshell-decoder")).toBe("misc");
    expect(normalizeEvidenceModule("media-speech")).toBe("media");
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

  it("keeps optional-contract evidence fixtures stable for ja3, webshell, china chopper, dnp3, ioc, playbook, and rule rows", () => {
    const records = parseEvidenceRecords({
      records: [
        {
          id: "hunt:ja3",
          module: "threat-hunting",
          source_module: "tls",
          source_type: "ja3",
          family: "ja3",
          summary: "JA3 fingerprint matched suspicious client",
          value: "72a589da586844d7f0818ce684948eea",
          confidence: 70,
          severity: "medium",
          tags: ["ja3", "tls", 443],
        },
        {
          id: "hunt:ja3s",
          module: "threat-hunting",
          source_module: "tls",
          source_type: "ja3s",
          family: "ja3s",
          summary: "JA3S fingerprint matched suspicious server",
          value: "b742b407517bac9536a77a7b0fee28e9",
          confidence: 65,
          severity: "medium",
          tags: ["ja3s", "server"],
        },
        {
          id: "misc:webshell",
          module: "webshell-decoder",
          source_type: "webshell",
          family: "antsword_like",
          summary: "WebShell payload candidate",
          tags: ["webshell", "decoder"],
          caveats: ["requires manual review"],
        },
        {
          id: "misc:china-chopper",
          module: "misc",
          source_type: "china_chopper",
          family: "china_chopper",
          summary: "China Chopper POST parameter pattern",
          value: "password=z1",
          severity: "high",
          tags: ["webshell", "china-chopper"],
        },
        {
          id: "industrial:dnp3",
          module: "industrial-analysis",
          source_module: "dnp3",
          source_type: "dnp3",
          family: "dnp3",
          summary: "DNP3 operate command",
          value: "function=operate",
          severity: "high",
          tags: ["dnp3", "operate"],
        },
        {
          id: "hunt:ioc",
          module: "yara-threat-hunting",
          source_type: "ioc",
          summary: "IOC domain matched deny list",
          value: "evil.example",
          tags: ["ioc", "domain"],
        },
        {
          id: "hunt:playbook",
          module: "threat-hunting",
          source_type: "playbook",
          summary: "Playbook correlation produced lead",
          tags: ["playbook", "correlation"],
        },
        {
          id: "hunt:rule",
          module: "threat-hunting",
          source_type: "rule",
          summary: "Rule hit promoted to evidence",
          tags: ["rule", "sigma"],
        },
      ],
    });

    expect(records).toHaveLength(8);
    expect(records).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "hunt:ja3",
          module: "hunting",
          sourceModule: "tls",
          sourceType: "ja3",
          family: "ja3",
          value: "72a589da586844d7f0818ce684948eea",
          tags: ["ja3", "tls", "443"],
        }),
        expect.objectContaining({
          id: "hunt:ja3s",
          module: "hunting",
          sourceType: "ja3s",
          family: "ja3s",
          tags: ["ja3s", "server"],
        }),
        expect.objectContaining({
          id: "misc:webshell",
          module: "misc",
          sourceType: "webshell",
          family: "antsword_like",
          caveats: ["requires manual review"],
        }),
        expect.objectContaining({
          id: "misc:china-chopper",
          module: "misc",
          sourceType: "china_chopper",
          family: "china_chopper",
          value: "password=z1",
        }),
        expect.objectContaining({
          id: "industrial:dnp3",
          module: "industrial",
          sourceModule: "dnp3",
          sourceType: "dnp3",
          family: "dnp3",
        }),
        expect.objectContaining({
          id: "hunt:ioc",
          module: "hunting",
          sourceType: "ioc",
          value: "evil.example",
        }),
        expect.objectContaining({
          id: "hunt:playbook",
          module: "hunting",
          sourceType: "playbook",
          tags: ["playbook", "correlation"],
        }),
        expect.objectContaining({
          id: "hunt:rule",
          module: "hunting",
          sourceType: "rule",
          tags: ["rule", "sigma"],
        }),
      ]),
    );
  });

  it("keeps absent optional evidence fields undefined instead of inventing version, hash, or actor data", () => {
    const [record] = parseEvidenceRecords({
      records: [
        {
          id: "misc:webshell-minimal",
          module: "webshell-decoder",
          source_type: "webshell",
          summary: "WebShell candidate without exposed version",
          tags: ["webshell"],
        },
      ],
    });

    expect(record).toMatchObject({
      id: "misc:webshell-minimal",
      module: "misc",
      sourceType: "webshell",
      summary: "WebShell candidate without exposed version",
      tags: ["webshell"],
    });
    expect(record.family).toBeUndefined();
    expect(record.value).toBeUndefined();
    expect(record.actorId).toBeUndefined();
    expect(record.actorName).toBeUndefined();
    expect(record.sourceModule).toBeUndefined();
    expect(record.host).toBeUndefined();
    expect(record.uri).toBeUndefined();
  });
});
