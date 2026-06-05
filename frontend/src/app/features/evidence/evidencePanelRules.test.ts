import { describe, expect, it } from "vitest";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import {
  buildEvidenceCsv,
  collectEvidenceCaveats,
  countEvidenceSeverity,
  evidenceFamilyLabel,
  evidenceIocLabel,
  evidencePlaybookLabel,
  evidenceProtocolLabel,
  evidenceRuleLabel,
  evidenceSourceTypeLabel,
  evidenceVersionLabel,
  filterEvidenceRecords,
  hasValidPacketId,
  hasValidStreamId,
  moduleLabel,
  sortEvidenceRecords,
} from "./evidencePanelRules";

function record(overrides: Partial<UnifiedEvidenceRecord>): UnifiedEvidenceRecord {
  return {
    id: "evidence-1",
    module: "c2",
    sourceType: "stream",
    summary: "C2 candidate",
    confidence: 50,
    confidenceLabel: "medium",
    severity: "medium",
    tags: [],
    caveats: [],
    ...overrides,
  };
}

describe("evidence panel rules", () => {
  it("filters by severity and searchable fields", () => {
    const rows = [
      record({ id: "one", severity: "high", summary: "VShell beacon", tags: ["vshell"] }),
      record({ id: "two", severity: "medium", value: "10.0.0.5", tags: ["modbus"] }),
    ];

    expect(filterEvidenceRecords(rows, "VSHELL", "high").map((item) => item.id)).toEqual(["one"]);
    expect(filterEvidenceRecords(rows, "10.0.0.5", "all").map((item) => item.id)).toEqual(["two"]);
  });

  it("sorts by severity first and confidence second", () => {
    const rows = [
      record({ id: "low", severity: "low", confidence: 90 }),
      record({ id: "high-low-confidence", severity: "high", confidence: 10 }),
      record({ id: "high-high-confidence", severity: "high", confidence: 80 }),
    ];

    expect(sortEvidenceRecords(rows).map((item) => item.id)).toEqual([
      "high-high-confidence",
      "high-low-confidence",
      "low",
    ]);
  });

  it("counts severity, exports csv, and deduplicates caveats", () => {
    const rows = [
      record({
        id: "one",
        severity: "critical",
        summary: 'quoted "summary"',
        packetId: 7,
        tags: ["a", "b"],
        caveats: ["review"],
      }),
      record({ id: "two", severity: "info", caveats: ["review", "weak signal"] }),
    ];

    expect(countEvidenceSeverity(rows)).toMatchObject({ critical: 1, info: 1, high: 0 });
    expect(buildEvidenceCsv(rows)).toContain('"quoted ""summary"""');
    expect(collectEvidenceCaveats(rows)).toEqual(["review", "weak signal"]);
    expect(moduleLabel("media")).toBe("媒体");
    expect(moduleLabel("vehicle")).toBe("车机");
  });

  it("filters optional-contract evidence fixtures by source type, tags, and values without relying on missing fields", () => {
    const rows = [
      record({
        id: "ja3",
        module: "hunting",
        sourceType: "ja3",
        summary: "TLS client fingerprint",
        ja3Hash: "72a589",
        tags: ["tls"],
      }),
      record({
        id: "ja3s",
        module: "hunting",
        sourceType: "ja3s",
        summary: "TLS server fingerprint",
        ja3sHash: "b742b4",
        tags: ["server"],
      }),
      record({
        id: "webshell",
        module: "misc",
        sourceType: "webshell",
        summary: "WebShell payload candidate",
        tags: ["webshell", "antsword"],
      }),
      record({
        id: "china-chopper",
        module: "misc",
        sourceType: "china_chopper",
        summary: "China Chopper parameter",
        value: "password=z1",
        tags: ["china-chopper"],
      }),
      record({
        id: "dnp3",
        module: "industrial",
        sourceType: "dnp3",
        summary: "DNP3 operate command",
        value: "function=operate",
        protocol: "dnp3",
        tags: [],
      }),
      record({
        id: "ioc",
        module: "hunting",
        sourceType: "ioc",
        summary: "IOC match",
        iocType: "domain",
        iocValue: "evil.example",
        tags: [],
      }),
      record({
        id: "playbook",
        module: "hunting",
        sourceType: "playbook",
        summary: "Correlation lead",
        playbookId: "PB-001",
        playbookName: "Playbook: beacon triage",
        tags: [],
      }),
      record({
        id: "rule",
        module: "hunting",
        sourceType: "rule",
        summary: "Detection hit",
        ruleId: "SIGMA-001",
        ruleName: "Suspicious Sigma rule",
        tags: [],
      }),
    ];

    expect(filterEvidenceRecords(rows, "72a589", "all").map((item) => item.id)).toEqual(["ja3"]);
    expect(filterEvidenceRecords(rows, "b742b4", "all").map((item) => item.id)).toEqual(["ja3s"]);
    expect(filterEvidenceRecords(rows, "password=z1", "all").map((item) => item.id)).toEqual(["china-chopper"]);
    expect(filterEvidenceRecords(rows, "dnp3", "all").map((item) => item.id)).toEqual(["dnp3"]);
    expect(filterEvidenceRecords(rows, "evil.example", "all").map((item) => item.id)).toEqual(["ioc"]);
    expect(filterEvidenceRecords(rows, "playbook", "all").map((item) => item.id)).toEqual(["playbook"]);
    expect(filterEvidenceRecords(rows, "sigma", "all").map((item) => item.id)).toEqual(["rule"]);
  });

  it("exports richer evidence fields for hashes, iocs, family, protocol, playbooks, rules, and tags", () => {
    const rows = [
      record({
        module: "hunting",
        sourceType: "ioc",
        displayName: "Beacon IOC",
        family: "vshell",
        version: "3.x",
        protocol: "tls",
        ruleId: "SIGMA-001",
        ruleName: "Suspicious beacon",
        playbookId: "PB-001",
        playbookName: "Beacon triage",
        iocType: "domain",
        iocValue: "evil.example",
        ja3Hash: "72a589",
        ja3sHash: "b742b4",
        metadata: { technique: "T1071.001" },
        tags: ["T1071.001", "beacon"],
      }),
    ];

    const csv = buildEvidenceCsv(rows);

    expect(csv.split("\n")[0]).toContain("displayName,family,version,protocol,ruleId,ruleName");
    expect(csv).toContain("Beacon IOC");
    expect(csv).toContain("vshell");
    expect(csv).toContain("tls");
    expect(csv).toContain("SIGMA-001");
    expect(csv).toContain("PB-001");
    expect(csv).toContain("evil.example");
    expect(csv).toContain("72a589");
    expect(csv).toContain('"{""technique"":""T1071.001""}"');
    expect(csv).toContain("T1071.001; beacon");
  });

  it("exports sparse optional-contract records without undefined text or invented packet data", () => {
    const rows = [
      record({
        id: "webshell-minimal",
        module: "misc",
        sourceType: "webshell",
        summary: "WebShell candidate without exposed version",
        confidence: undefined,
        packetId: undefined,
        tags: [],
      }),
      record({
        id: "ioc-minimal",
        module: "hunting",
        sourceType: "ioc",
        summary: "IOC feed unavailable for current capture",
        value: undefined,
        confidence: undefined,
        packetId: undefined,
        tags: [],
      }),
    ];

    const csv = buildEvidenceCsv(rows);

    expect(csv).toContain("webshell");
    expect(csv).toContain("ioc");
    expect(csv).not.toContain("undefined");
    expect(csv).not.toContain(",,undefined");
    expect(csv.split("\n")[1]).toContain('"WebShell candidate without exposed version"');
    expect(csv.split("\n")[2]).toContain('"IOC feed unavailable for current capture"');
  });

  it("normalizes task-8 labels and unavailable states through shared helpers", () => {
    const chinaChopper = record({
      sourceType: "china_chopper",
      family: "caidao",
      summary: "China Chopper parameter",
    });
    const webshell = record({
      sourceType: "webshell",
      family: "antsword_like",
      summary: "WebShell payload candidate",
    });
    const ja3 = record({ sourceType: "ja3", summary: "TLS client fingerprint" });
    const ja3s = record({ sourceType: "ja3s", summary: "TLS server fingerprint" });
    const dnp3 = record({ sourceType: "dnp3", summary: "DNP3 operate command" });
    const ioc = record({ sourceType: "ioc", summary: "IOC evidence" });
    const playbook = record({ sourceType: "playbook", summary: "Playbook evidence" });
    const rule = record({ sourceType: "rule", summary: "Rule evidence" });

    expect(evidenceSourceTypeLabel(chinaChopper.sourceType)).toBe("菜刀 / China Chopper");
    expect(evidenceFamilyLabel(chinaChopper)).toBe("菜刀 / China Chopper");
    expect(evidenceSourceTypeLabel(webshell.sourceType)).toBe("WebShell");
    expect(evidenceVersionLabel(webshell)).toBe("未提供");
    expect(evidenceSourceTypeLabel(ja3.sourceType)).toBe("JA3");
    expect(evidenceSourceTypeLabel(ja3s.sourceType)).toBe("JA3S");
    expect(evidenceSourceTypeLabel(dnp3.sourceType)).toBe("DNP3");
    expect(evidenceProtocolLabel(dnp3)).toBe("DNP3");
    expect(evidenceSourceTypeLabel(ioc.sourceType)).toBe("IOC");
    expect(evidenceIocLabel(ioc)).toBe("IOC API unavailable");
    expect(evidenceSourceTypeLabel(playbook.sourceType)).toBe("Playbook");
    expect(evidencePlaybookLabel(playbook)).toBe("Playbook 未提供");
    expect(evidenceSourceTypeLabel(rule.sourceType)).toBe("Rule");
    expect(evidenceRuleLabel(rule)).toBe("Rule 未提供");
  });

  it("treats packet and stream navigation guards independently", () => {
    expect(hasValidPacketId(undefined)).toBe(false);
    expect(hasValidPacketId(0)).toBe(false);
    expect(hasValidPacketId(12)).toBe(true);
    expect(hasValidStreamId(undefined)).toBe(false);
    expect(hasValidStreamId(-1)).toBe(false);
    expect(hasValidStreamId(7)).toBe(true);
  });
});
