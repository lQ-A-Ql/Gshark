import { describe, expect, it } from "vitest";
import { asC2SampleAnalysis } from "./c2SampleMapper";

describe("c2SampleMapper", () => {
  it("maps CS and VShell sample analysis payloads into frontend shape", () => {
    const result = asC2SampleAnalysis({
      total_matched_packets: 9,
      families: [{ label: "cs", count: 2 }],
      conversations: [{ label: "10.0.0.1 -> 10.0.0.2", protocol: "HTTP", count: 3 }],
      notes: ["sample note"],
      cs: {
        candidate_count: 2,
        matched_rule_count: 1,
        channels: [{ label: "http", count: 2 }],
        indicators: [{ label: "beacon", count: 1 }],
        conversations: [{ label: "stream 4", protocol: "TCP", count: 2 }],
        beacon_patterns: [{ name: "jitter", value: "low", confidence: 80, summary: "stable" }],
        host_uri_aggregates: [
          {
            host: "c2.example",
            uri: "/submit.php",
            channel: "http",
            total: 7,
            get_count: 2,
            post_count: 5,
            methods: [{ label: "POST", count: 5 }],
            first_time: "10:00:00",
            last_time: "10:05:00",
            avg_interval: "60s",
            jitter: "5s",
            intervals: [60, "0", -1, "bad"],
            streams: [4, "0", 6],
            packets: [1, 0, 9],
            representative_packet: 9,
            confidence: 90,
            signal_tags: ["http-post"],
            score_factors: [{ name: "uri", weight: 2, direction: "positive", summary: "known shape" }],
            summary: "endpoint aggregate",
          },
        ],
        dns_aggregates: [
          {
            qname: "x.example",
            total: 2,
            max_label_length: 12,
            query_types: [{ label: "TXT", count: 2 }],
            txt_count: 2,
            null_count: 0,
            cname_count: 0,
            request_count: 1,
            response_count: 1,
            intervals: [30, "bad"],
            packets: [8],
            summary: "dns aggregate",
          },
        ],
        stream_aggregates: [
          {
            stream_id: 4,
            protocol: "TCP",
            total_packets: 12,
            arch_markers: [{ label: "x64", count: 1 }],
            length_prefix_count: 3,
            short_packets: 1,
            long_packets: 2,
            transitions: 4,
            heartbeat_avg: "10s",
            heartbeat_jitter: "1s",
            intervals: [10, 0, "bad"],
            has_websocket: true,
            ws_params: "verifykey",
            listener_hints: [{ label: "beacon", count: 1 }],
            packets: [1, 2],
            confidence: 75,
            summary: "stream aggregate",
          },
        ],
        candidates: [
          {
            packet_id: 9,
            stream_id: 4,
            time: "10:00:01",
            family: "cs",
            channel: "http",
            source: "10.0.0.1",
            destination: "10.0.0.2",
            host: "c2.example",
            uri: "/submit.php",
            method: "POST",
            indicator_type: "uri",
            indicator_value: "/submit.php",
            confidence: 88,
            summary: "candidate",
            evidence: "payload",
            tags: ["post", 42],
            actor_hints: ["unknown"],
            sample_family: "beacon",
            campaign_stage: "c2",
            transport_traits: ["http"],
            infrastructure_hints: ["host"],
            ttp_tags: ["T1071"],
            attribution_confidence: 55,
          },
        ],
        notes: ["cs note"],
        related_actors: [{ label: "actor", count: 1 }],
        delivery_chains: [{ label: "http", count: 1 }],
      },
      vshell: {
        candidates: [{ packet_id: 11, family: "vshell", summary: "vshell candidate" }],
      },
    });

    expect(result.totalMatchedPackets).toBe(9);
    expect(result.families).toEqual([{ label: "cs", count: 2 }]);
    expect(result.conversations[0]).toMatchObject({ label: "10.0.0.1 -> 10.0.0.2", protocol: "HTTP" });
    expect(result.cs.candidateCount).toBe(2);
    expect(result.cs.hostUriAggregates?.[0]).toMatchObject({
      host: "c2.example",
      uri: "/submit.php",
      getCount: 2,
      postCount: 5,
      intervals: [60],
      streams: [4, 6],
      packets: [1, 9],
    });
    expect(result.cs.dnsAggregates?.[0]).toMatchObject({ qname: "x.example", intervals: [30] });
    expect(result.cs.streamAggregates?.[0]).toMatchObject({
      streamId: 4,
      hasWebSocket: true,
      intervals: [10],
      packets: [1, 2],
    });
    expect(result.cs.candidates[0]).toMatchObject({
      packetId: 9,
      streamId: 4,
      family: "cs",
      indicatorType: "uri",
      tags: ["post", "42"],
      actorHints: ["unknown"],
      ttpTags: ["T1071"],
      attributionConfidence: 55,
    });
    expect(result.vshell.candidates[0]).toMatchObject({ packetId: 11, family: "vshell" });
    expect(result.notes).toEqual(["sample note"]);
  });

  it("uses safe defaults for missing or malformed payload sections", () => {
    const result = asC2SampleAnalysis({
      cs: {
        candidates: [{ packet_id: 1, family: "unknown", summary: "fallback" }],
        notes: "not-array",
      },
    });

    expect(result.families).toEqual([]);
    expect(result.cs.candidates[0]).toMatchObject({
      packetId: 1,
      family: "cs",
      summary: "fallback",
    });
    expect(result.cs.notes).toEqual([]);
    expect(result.vshell.candidates).toEqual([]);
  });
});
