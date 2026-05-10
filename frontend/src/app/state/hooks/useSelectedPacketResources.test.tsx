import { renderHook, waitFor } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useSelectedPacketResources } from "./useSelectedPacketResources";

const packet = (id: number): Packet => ({ id, proto: "TCP" }) as Packet;

function useResourcesHarness(options: {
  selectedPacketId: number | null;
  selectedPacket: Packet | null;
  loadPacket: (packetId: number, signal: AbortSignal) => Promise<Packet>;
  loadRawHex: (packetId: number, signal: AbortSignal) => Promise<string>;
  loadLayers: (packetId: number, signal: AbortSignal) => Promise<Record<string, unknown> | null>;
}) {
  const captureTaskScopeRef = useRef(createCaptureTaskScope());
  const [detail, setDetail] = useState<Packet | null>(null);
  const [rawHex, setRawHex] = useState("");
  const [layers, setLayers] = useState<Record<string, unknown> | null>(null);

  useSelectedPacketResources({
    selectedPacketId: options.selectedPacketId,
    selectedPacket: options.selectedPacket,
    selectedPacketDetail: detail,
    captureTaskScopeRef,
    loadPacket: options.loadPacket,
    loadRawHex: options.loadRawHex,
    loadLayers: options.loadLayers,
    setSelectedPacketDetail: setDetail,
    setSelectedPacketRawHex: setRawHex,
    setSelectedPacketLayers: setLayers,
  });

  return { detail, rawHex, layers };
}

describe("useSelectedPacketResources", () => {
  it("loads packet detail, raw hex, and layers for selected packets", async () => {
    const loadPacket = vi.fn(async (packetId: number) => packet(packetId));
    const loadRawHex = vi.fn(async () => "aa bb");
    const layers = { frame: { frame_number: "7" } };
    const loadLayers = vi.fn(async () => layers);
    const { result } = renderHook(() =>
      useResourcesHarness({
        selectedPacketId: 7,
        selectedPacket: packet(7),
        loadPacket,
        loadRawHex,
        loadLayers,
      }),
    );

    await waitFor(() => {
      expect(result.current.detail?.id).toBe(7);
      expect(result.current.rawHex).toBe("aa bb");
      expect(result.current.layers).toEqual(layers);
    });
    expect(loadPacket).toHaveBeenCalledWith(7, expect.any(AbortSignal));
    expect(loadRawHex).toHaveBeenCalledWith(7, expect.any(AbortSignal));
    expect(loadLayers).toHaveBeenCalledWith(7, expect.any(AbortSignal));
  });
});
