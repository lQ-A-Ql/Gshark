import { describe, expect, it } from "vitest";
import { filterEvidenceRecords } from "./evidencePanelRules";
import { optionalContractRows, record } from "./evidencePanelRules.testFixtures";

describe("evidence filter rules", () => {
  it("filters by severity and searchable fields", () => {
    const rows = [
      record({ id: "one", severity: "high", summary: "VShell beacon", tags: ["vshell"] }),
      record({ id: "two", severity: "medium", value: "10.0.0.5", tags: ["modbus"] }),
    ];

    expect(filterEvidenceRecords(rows, "VSHELL", "high").map((item) => item.id)).toEqual(["one"]);
    expect(filterEvidenceRecords(rows, "10.0.0.5", "all").map((item) => item.id)).toEqual(["two"]);
  });

  it("finds optional-contract evidence through source type, tags, hashes, values, and rule fields", () => {
    const rows = optionalContractRows();

    expect(filterEvidenceRecords(rows, "72a589", "all").map((item) => item.id)).toEqual(["ja3"]);
    expect(filterEvidenceRecords(rows, "b742b4", "all").map((item) => item.id)).toEqual(["ja3s"]);
    expect(filterEvidenceRecords(rows, "password=z1", "all").map((item) => item.id)).toEqual(["china-chopper"]);
    expect(filterEvidenceRecords(rows, "dnp3", "all").map((item) => item.id)).toEqual(["dnp3"]);
    expect(filterEvidenceRecords(rows, "evil.example", "all").map((item) => item.id)).toEqual(["ioc"]);
    expect(filterEvidenceRecords(rows, "playbook", "all").map((item) => item.id)).toEqual(["playbook"]);
    expect(filterEvidenceRecords(rows, "sigma", "all").map((item) => item.id)).toEqual(["rule"]);
  });
});
