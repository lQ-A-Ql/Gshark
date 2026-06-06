import { describe, expect, it } from "vitest";
import { buildEvidenceFacetGroups, buildEvidenceSummaryMetrics, collectEvidenceCaveats, countEvidenceSeverity } from "./evidencePanelRules";
import { record } from "./evidencePanelRules.testFixtures";

describe("evidence count rules", () => {
  it("counts severity, caveats, facets, and summary metrics", () => {
    const rows = [
      record({ id: "one", severity: "critical", packetId: 7, streamId: 3, caveats: ["review"], feature: "ja3" }),
      record({ id: "two", severity: "info", caveats: ["review", "weak signal"], entityType: "domain" }),
    ];

    expect(countEvidenceSeverity(rows)).toMatchObject({ critical: 1, info: 1, high: 0 });
    expect(collectEvidenceCaveats(rows)).toEqual(["review", "weak signal"]);
    expect(buildEvidenceFacetGroups(rows).features).toEqual([{ value: "ja3", label: "ja3", count: 1 }]);
    expect(buildEvidenceSummaryMetrics(rows, rows)).toMatchObject({ totalRecords: 2, mappedPacketCount: 1, mappedStreamCount: 1 });
  });
});
