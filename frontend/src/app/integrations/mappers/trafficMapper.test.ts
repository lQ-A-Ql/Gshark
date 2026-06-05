import { describe, expect, it } from "vitest";
import { asGlobalTrafficStats } from "./trafficMapper";

describe("trafficMapper", () => {
  it("maps global traffic stats buckets", () => {
    const result = asGlobalTrafficStats({
      total_packets: 100,
      protocol_kinds: 3,
      timeline: [
        { label: "12:00:02.000", count: 1 },
        { label: "12:00:00.000", count: 3 },
        { label: "bad", count: 99 },
        { label: "12:00:00.900", count: 2 },
      ],
      protocol_dist: [{ label: "TCP", count: 70 }],
      top_talkers: [{ label: "10.0.0.1", count: 30 }],
      top_conversations: [{ src: " 10.0.0.1 ", dst: "10.0.0.2 ", count: "12" }],
      top_hostnames: [{ label: "host", count: 2 }],
      top_domains: [{ label: "example.com", count: 3 }],
      top_src_ips: [{ label: "10.0.0.1", count: 4 }],
      top_dst_ips: [{ label: "10.0.0.2", count: 5 }],
      top_computer_names: [{ label: "DESKTOP", count: 1 }],
      top_dest_ports: [{ label: "443", count: 6 }],
      top_src_ports: [{ label: "50000", count: 7 }],
    });

    expect(result.totalPackets).toBe(100);
    expect(result.timeline).toEqual([
      { label: "12:00:00", count: 5 },
      { label: "12:00:02", count: 1 },
    ]);
    expect(result.protocolDist).toEqual([{ label: "TCP", count: 70 }]);
    expect(result.topDestPorts).toEqual([{ label: "443", count: 6 }]);
    expect(result.topConversations).toEqual([{ src: "10.0.0.1", dst: "10.0.0.2", count: 12 }]);
  });

  it("normalizes, sorts, and filters malformed timeline buckets", () => {
    const result = asGlobalTrafficStats({
      timeline: [
        { label: "12:00:02.400", count: 1 },
        { label: "12:00:00.900", count: 2 },
        { label: "12:00:00.100", count: 3 },
        { label: "bad", count: 99 },
        { label: "12:00:03", count: Number.NaN },
        { label: "12:00:01", count: -5 },
      ],
    });

    expect(result.timeline).toEqual([
      { label: "12:00:00", count: 5 },
      { label: "12:00:02", count: 1 },
    ]);
  });

  it("uses empty defaults for missing arrays", () => {
    const result = asGlobalTrafficStats({});
    expect(result.timeline).toEqual([]);
    expect(result.topTalkers).toEqual([]);
    expect(result.topConversations).toEqual([]);
  });

  it("drops malformed top conversation entries", () => {
    const result = asGlobalTrafficStats({
      top_conversations: [
        { src: "10.0.0.1", dst: "10.0.0.2", count: 3 },
        { src: "   ", dst: "10.0.0.2", count: 9 },
        { src: "10.0.0.3", dst: "", count: 5 },
      ],
    });

    expect(result.topConversations).toEqual([{ src: "10.0.0.1", dst: "10.0.0.2", count: 3 }]);
  });

  it("uses empty defaults for malformed payloads", () => {
    expect(asGlobalTrafficStats("bad")).toMatchObject({ totalPackets: 0, protocolDist: [] });
  });
});
