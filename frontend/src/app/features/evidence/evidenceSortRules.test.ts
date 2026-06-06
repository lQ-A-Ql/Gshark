import { describe, expect, it } from "vitest";
import { sortEvidenceRecords } from "./evidencePanelRules";
import { record } from "./evidencePanelRules.testFixtures";

describe("evidence sort rules", () => {
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
});
