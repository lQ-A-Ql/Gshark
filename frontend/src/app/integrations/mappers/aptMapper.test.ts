import { describe, expect, it } from "vitest";
import { asAPTAnalysis } from "./aptMapper";

describe("aptMapper", () => {
  it("maps APT actor profiles and evidence records", () => {
    const result = asAPTAnalysis({
      total_evidence: 3,
      actors: [{ label: "Silver Fox", count: 2 }],
      sample_families: [{ label: "cs", count: 1 }],
      campaign_stages: [{ label: "c2", count: 1 }],
      transport_traits: [{ label: "http", count: 1 }],
      infrastructure_hints: [{ label: "cdn", count: 1 }],
      related_c2_families: [{ label: "vshell", count: 1 }],
      profiles: [
        {
          id: "silver-fox",
          name: "Silver Fox",
          aliases: ["Swimming Snake", 7],
          summary: "profile",
          confidence: 82,
          evidence_count: 2,
          sample_families: [{ label: "cs", count: 1 }],
          campaign_stages: [{ label: "delivery", count: 1 }],
          transport_traits: [{ label: "http", count: 1 }],
          infrastructure_hints: [{ label: "host", count: 1 }],
          related_c2_families: [{ label: "cs", count: 1 }],
          ttp_tags: [{ label: "T1071", count: 1 }],
          score_factors: [{ name: "host", weight: 2, direction: "positive", source_module: "c2", summary: "hit" }],
          notes: ["review"],
        },
      ],
      evidence: [
        {
          packet_id: 9,
          stream_id: 4,
          time: "10:00:00",
          actor_id: "silver-fox",
          actor_name: "Silver Fox",
          source_module: "c2",
          family: "cs",
          evidence_type: "host",
          evidence_value: "c2.example",
          confidence: 88,
          source: "10.0.0.1",
          destination: "10.0.0.2",
          host: "c2.example",
          uri: "/api",
          sample_family: "beacon",
          campaign_stage: "c2",
          transport_traits: ["http"],
          infrastructure_hints: ["host"],
          ttp_tags: ["T1071"],
          tags: ["apt", 42],
          score_factors: [{ name: "uri", weight: 1, direction: "positive", source_module: "c2" }],
          summary: "evidence",
          evidence: "payload",
        },
      ],
      notes: ["apt note"],
    });

    expect(result.totalEvidence).toBe(3);
    expect(result.actors).toEqual([{ label: "Silver Fox", count: 2 }]);
    expect(result.profiles[0]).toMatchObject({
      id: "silver-fox",
      aliases: ["Swimming Snake", "7"],
      evidenceCount: 2,
      notes: ["review"],
    });
    expect(result.profiles[0].scoreFactors?.[0]).toMatchObject({
      name: "host",
      sourceModule: "c2",
    });
    expect(result.evidence[0]).toMatchObject({
      packetId: 9,
      streamId: 4,
      actorId: "silver-fox",
      evidenceType: "host",
      tags: ["apt", "42"],
    });
    expect(result.notes).toEqual(["apt note"]);
  });

  it("returns empty defaults for malformed payload sections", () => {
    const result = asAPTAnalysis({ profiles: "bad", evidence: null });
    expect(result.profiles).toEqual([]);
    expect(result.evidence).toEqual([]);
    expect(result.notes).toEqual([]);
  });
});
