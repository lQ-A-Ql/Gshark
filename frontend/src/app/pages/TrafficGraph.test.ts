import { describe, expect, it } from "vitest";
import { buildStatsFromPackets } from "../features/traffic/useTrafficGraph";
import type { Packet } from "../core/types";

describe("buildStatsFromPackets", () => {
  it("collects domains, computer names, and src/dst ip buckets for fallback traffic stats", () => {
    const packets: Packet[] = [
      {
        id: 1,
        time: "12:00:00.000",
        src: "10.0.0.2",
        srcPort: 52344,
        dst: "93.184.216.34",
        dstPort: 443,
        proto: "TLS",
        displayProtocol: "TLSv1.3",
        length: 128,
        info: "Client Hello SNI: example.com",
        payload: "",
      },
      {
        id: 2,
        time: "12:00:00.500",
        src: "10.0.0.2",
        srcPort: 52345,
        dst: "93.184.216.34",
        dstPort: 80,
        proto: "HTTP",
        displayProtocol: "HTTP",
        length: 256,
        info: "GET / HTTP/1.1\nComputer Name: WS-01",
        payload: "Host: example.com\r\n\r\n",
      },
    ];

    const stats = buildStatsFromPackets(packets);

    expect(stats.totalPackets).toBe(2);
    expect(stats.protocolKinds).toBe(2);
    expect(stats.timeline).toEqual([{ label: "12:00:00", count: 2 }]);
    expect(stats.topDomains[0]).toEqual({ label: "example.com", count: 2 });
    expect(stats.topHostnames[0]).toEqual({ label: "example.com", count: 2 });
    expect(stats.topComputerNames[0]).toEqual({ label: "WS-01", count: 1 });
    expect(stats.topTalkers).toEqual([
      { label: "10.0.0.2", count: 2 },
      { label: "93.184.216.34", count: 2 },
    ]);
    expect(stats.topConversations).toEqual([
      { src: "10.0.0.2", dst: "93.184.216.34", count: 2 },
    ]);
    expect(stats.topSrcIPs[0]).toEqual({ label: "10.0.0.2", count: 2 });
    expect(stats.topDstIPs[0]).toEqual({ label: "93.184.216.34", count: 2 });
    expect(stats.topDestPorts.map((item) => item.label)).toContain("443");
    expect(stats.topDestPorts.map((item) => item.label)).toContain("80");
    expect(stats.topSrcPorts.map((item) => item.label)).toContain("52344");
    expect(stats.topSrcPorts.map((item) => item.label)).toContain("52345");
  });

  it("builds a sorted per-second fallback timeline from mixed packet time formats", () => {
    const packets: Packet[] = [
      {
        id: 1,
        time: "1717588802000",
        src: "10.0.0.1",
        srcPort: 1111,
        dst: "10.0.0.2",
        dstPort: 80,
        proto: "HTTP",
        displayProtocol: "HTTP",
        length: 64,
        info: "",
        payload: "",
      },
      {
        id: 2,
        time: "12:00:00.900",
        src: "10.0.0.1",
        srcPort: 1112,
        dst: "10.0.0.3",
        dstPort: 80,
        proto: "HTTP",
        displayProtocol: "HTTP",
        length: 64,
        info: "",
        payload: "",
      },
      {
        id: 3,
        time: "bad-time",
        src: "10.0.0.1",
        srcPort: 1113,
        dst: "10.0.0.4",
        dstPort: 80,
        proto: "HTTP",
        displayProtocol: "HTTP",
        length: 64,
        info: "",
        payload: "",
      },
      {
        id: 4,
        time: "12:00:00.100",
        src: "10.0.0.1",
        srcPort: 1114,
        dst: "10.0.0.5",
        dstPort: 80,
        proto: "HTTP",
        displayProtocol: "HTTP",
        length: 64,
        info: "",
        payload: "",
      },
    ];

    const stats = buildStatsFromPackets(packets);

    expect(stats.timeline).toEqual([
      { label: "12:00:00", count: 2 },
      { label: "12:00:02", count: 1 },
    ]);
  });
});
