import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useSelectedPacketState } from "./useSelectedPacketState";

const packet = (id: number, proto = "TCP"): Packet =>
  ({
    id,
    proto,
    src: "10.0.0.1",
    dst: "10.0.0.2",
    length: 54,
  }) as Packet;

describe("useSelectedPacketState", () => {
  it("owns selection state and loads selected packet artifacts", async () => {
    const captureTaskScopeRef = { current: createCaptureTaskScope() };
    const loadPacket = vi.fn(async (packetId: number) => packet(packetId, "HTTP"));
    const loadRawHex = vi.fn(async () => "68 69");
    const layers = { http: { request_method: "GET" } };
    const loadLayers = vi.fn(async () => layers);

    const { result } = renderHook(() =>
      useSelectedPacketState({
        packets: [packet(1)],
        pageStart: 0,
        totalPackets: 1,
        pageSize: 50,
        captureTaskScopeRef,
        loadPacket,
        loadRawHex,
        loadLayers,
      }),
    );

    act(() => result.current.selectPacket(7));

    await waitFor(() => {
      expect(result.current.selectedPacketId).toBe(7);
      expect(result.current.selectedPacket?.id).toBe(7);
      expect(result.current.selectedPacketRawHex).toBe("68 69");
      expect(result.current.protocolTree.length).toBeGreaterThan(0);
    });
    expect(loadPacket).toHaveBeenCalledWith(7, expect.any(AbortSignal));
    expect(loadRawHex).toHaveBeenCalledWith(7, expect.any(AbortSignal));
    expect(loadLayers).toHaveBeenCalledWith(7, expect.any(AbortSignal));
  });
});
