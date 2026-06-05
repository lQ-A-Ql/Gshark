import { describe, expect, it } from "vitest";
import { buildTrafficTimelineEvidence, evidenceIsCommunityYara, evidenceIsYara } from "./trafficTimelineEvidence";
import type { UnifiedEvidenceRecord } from "../../core/types";

function record(overrides: Partial<UnifiedEvidenceRecord>): UnifiedEvidenceRecord {
  return {
    id: "ev-1",
    module: "hunting",
    sourceType: "YARA",
    summary: "YARA hit",
    confidenceLabel: "unknown",
    severity: "high",
    tags: ["yara"],
    caveats: [],
    ...overrides,
  };
}

describe("trafficTimelineEvidence", () => {
  it("maps timestamped evidence into timeline events", () => {
    const out = buildTrafficTimelineEvidence(
      [{ label: "12:00:01", count: 7 }],
      [record({ id: "ev-time", metadata: { timestamp: "12:00:01.250" }, packetId: 42 })],
    );

    expect(out.events).toHaveLength(1);
    expect(out.events[0]).toMatchObject({ id: "ev-time", label: "12:00:01", isYara: true, packetId: 42 });
    expect(out.unplacedRecords).toHaveLength(0);
  });

  it("keeps untimed evidence unplaced instead of fabricating a timeline point", () => {
    const out = buildTrafficTimelineEvidence([{ label: "12:00:01", count: 7 }], [record({ id: "ev-unplaced" })]);

    expect(out.events).toEqual([]);
    expect(out.unplacedRecords[0].id).toBe("ev-unplaced");
  });

  it("detects community YARA from rule metadata", () => {
    const ev = record({
      metadata: {
        timestamp: "12:00:01",
        rule_pack: "signature-base",
        rule_source: "Neo23x0/signature-base",
        community_rule: "true",
      },
    });

    expect(evidenceIsYara(ev)).toBe(true);
    expect(evidenceIsCommunityYara(ev)).toBe(true);
    expect(buildTrafficTimelineEvidence([{ label: "12:00:01", count: 7 }], [ev]).communityYaraCount).toBe(1);
  });
});
