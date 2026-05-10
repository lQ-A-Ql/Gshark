import { describe, expect, it } from "vitest";
import type { Packet } from "../core/types";
import { buildSentinelDerivedView } from "./sentinelDerivedView";

const packet = (id: number, extra: Partial<Packet> = {}): Packet =>
  ({
    id,
    time: "12:00:00.000",
    src: "192.168.1.10",
    srcPort: 50000,
    dst: "10.0.0.5",
    dstPort: 80,
    proto: "TCP",
    length: 60,
    info: "GET / HTTP/1.1",
    payload: "47:45:54",
    ...extra,
  }) as Packet;

describe("buildSentinelDerivedView", () => {
  it("builds selected packet, page metadata, and hex dump from packet state", () => {
    const packets = [packet(1), packet(2, { displayProtocol: "HTTP" })];
    const view = buildSentinelDerivedView({
      packets,
      selectedPacketId: 2,
      selectedPacketDetail: null,
      selectedPacketLayers: null,
      pageStart: 100,
      totalPackets: 230,
      pageSize: 50,
    });

    expect(view.filteredPackets).toBe(packets);
    expect(view.selectedPacket?.id).toBe(2);
    expect(view.currentPage).toBe(3);
    expect(view.totalPages).toBe(5);
    expect(view.hexDump).toContain("Frame 2 TCP Len=");
    expect(view.hexDump).toContain("60.Time=12:00:00");
    expect(view.protocolTree[0]?.label).toContain("Frame 2");
  });

  it("uses layer-derived protocol tree when packet layers are present", () => {
    const view = buildSentinelDerivedView({
      packets: [packet(7)],
      selectedPacketId: 7,
      selectedPacketDetail: null,
      selectedPacketLayers: {
        frame: { frame_frame_protocols: "eth:ip:tcp:http", frame_frame_number: "7", frame_frame_len: "60" },
        http: { "http.request.method": "GET" },
      },
      pageStart: 0,
      totalPackets: 1,
      pageSize: 50,
    });

    expect(view.protocolTree.map((node) => node.label)).toContain("Hypertext Transfer Protocol: GET");
  });
});
