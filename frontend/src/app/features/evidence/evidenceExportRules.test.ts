import { describe, expect, it } from "vitest";
import { buildEvidenceCsv } from "./evidencePanelRules";
import { record } from "./evidencePanelRules.testFixtures";

describe("evidence export rules", () => {
  it("exports csv with escaping and rich optional fields", () => {
    const csv = buildEvidenceCsv([
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
        summary: 'quoted "summary"',
        tags: ["T1071.001", "beacon"],
      }),
    ]);

    expect(csv.split("\n")[0]).toContain("displayName,family,version,protocol,ruleId,ruleName");
    expect(csv).toContain('"quoted ""summary"""');
    expect(csv).toContain('"{""technique"":""T1071.001""}"');
    expect(csv).toContain("T1071.001; beacon");
  });

  it("exports sparse records without undefined text or invented packet data", () => {
    const csv = buildEvidenceCsv([
      record({ id: "webshell-minimal", module: "misc", sourceType: "webshell", summary: "WebShell candidate without exposed version", confidence: undefined, packetId: undefined, tags: [] }),
      record({ id: "ioc-minimal", module: "hunting", sourceType: "ioc", summary: "IOC feed unavailable for current capture", value: undefined, confidence: undefined, packetId: undefined, tags: [] }),
    ]);

    expect(csv).not.toContain("undefined");
    expect(csv.split("\n")[1]).toContain('"WebShell candidate without exposed version"');
    expect(csv.split("\n")[2]).toContain('"IOC feed unavailable for current capture"');
  });
});
