import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Packet } from "../../core/types";
import { useSentinelDerivedView } from "./useSentinelDerivedView";

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

describe("useSentinelDerivedView", () => {
  it("memoizes derived packet view until state inputs change", () => {
    const packets = [packet(1), packet(2, { displayProtocol: "HTTP" })];
    let selectedPacketId: number | null = 2;
    const { rerender, result } = renderHook(() =>
      useSentinelDerivedView({
        packets,
        selectedPacketId,
        selectedPacketDetail: null,
        selectedPacketLayers: null,
        pageStart: 50,
        totalPackets: 120,
        pageSize: 50,
      }),
    );

    const firstView = result.current;
    rerender();

    expect(result.current).toBe(firstView);
    expect(result.current.selectedPacket?.id).toBe(2);
    expect(result.current.currentPage).toBe(2);
    expect(result.current.totalPages).toBe(3);

    selectedPacketId = 1;
    rerender();
    expect(result.current).not.toBe(firstView);
    expect(result.current.selectedPacket?.id).toBe(1);
  });
});
