import { describe, expect, it } from "vitest";
import type { UnifiedEvidenceRecord } from "./evidenceSchema";
import {
  buildEvidenceCsv,
  collectEvidenceCaveats,
  countEvidenceSeverity,
  filterEvidenceRecords,
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
    expect(moduleLabel("vehicle")).toBe("车机");
  });
});
