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
    expect(stats.topDomains[0]).toEqual({ label: "example.com", count: 2 });
    expect(stats.topHostnames[0]).toEqual({ label: "example.com", count: 2 });
    expect(stats.topComputerNames[0]).toEqual({ label: "WS-01", count: 1 });
    expect(stats.topSrcIPs[0]).toEqual({ label: "10.0.0.2", count: 2 });
    expect(stats.topDstIPs[0]).toEqual({ label: "93.184.216.34", count: 2 });
    expect(stats.topDestPorts.map((item: any) => item.label)).toContain("443");
    expect(stats.topDestPorts.map((item: any) => item.label)).toContain("80");
    expect(stats.topSrcPorts.map((item: any) => item.label)).toContain("52344");
    expect(stats.topSrcPorts.map((item: any) => item.label)).toContain("52345");
  });
});
