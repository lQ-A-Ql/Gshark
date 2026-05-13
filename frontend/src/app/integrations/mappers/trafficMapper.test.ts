import { describe, expect, it } from "vitest";
import { asGlobalTrafficStats } from "./trafficMapper";

describe("trafficMapper", () => {
  it("maps global traffic stats buckets", () => {
    const result = asGlobalTrafficStats({
      total_packets: 100,
      protocol_kinds: 3,
      timeline: [{ label: "00:00", count: 10 }],
      protocol_dist: [{ label: "TCP", count: 70 }],
      top_talkers: [{ label: "10.0.0.1", count: 30 }],
      top_hostnames: [{ label: "host", count: 2 }],
      top_domains: [{ label: "example.com", count: 3 }],
      top_src_ips: [{ label: "10.0.0.1", count: 4 }],
      top_dst_ips: [{ label: "10.0.0.2", count: 5 }],
      top_computer_names: [{ label: "DESKTOP", count: 1 }],
      top_dest_ports: [{ label: "443", count: 6 }],
      top_src_ports: [{ label: "50000", count: 7 }],
    });

    expect(result.totalPackets).toBe(100);
    expect(result.protocolDist).toEqual([{ label: "TCP", count: 70 }]);
    expect(result.topDestPorts).toEqual([{ label: "443", count: 6 }]);
  });

  it("uses empty defaults for missing arrays", () => {
    const result = asGlobalTrafficStats({});
    expect(result.timeline).toEqual([]);
    expect(result.topTalkers).toEqual([]);
  });

  it("uses empty defaults for malformed payloads", () => {
    expect(asGlobalTrafficStats("bad")).toMatchObject({ totalPackets: 0, protocolDist: [] });
  });
});
