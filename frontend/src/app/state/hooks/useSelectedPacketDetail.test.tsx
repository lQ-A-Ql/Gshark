import { renderHook, waitFor } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { useSelectedPacketDetail } from "./useSelectedPacketDetail";

function createPacket(id: number): Packet {
  return {
    id,
    time: "2026-05-08 19:20:00",
    src: "10.0.0.1",
    srcPort: 12345,
    dst: "10.0.0.2",
    dstPort: 443,
    proto: "TCP",
    length: 64,
    info: `packet-${id}`,
    payload: "",
  };
}

function useDetailHarness(options: {
  selectedPacketId: number | null;
  shouldLoad: boolean;
  loadPacket: (packetId: number, signal: AbortSignal) => Promise<Packet>;
  initial: Packet | null;
}) {
  const captureTaskScopeRef = useRef(createCaptureTaskScope());
  const [detail, setDetail] = useState<Packet | null>(options.initial);

  useSelectedPacketDetail({
    selectedPacketId: options.selectedPacketId,
    shouldLoad: options.shouldLoad,
    captureTaskScopeRef,
    loadPacket: options.loadPacket,
    setSelectedPacketDetail: setDetail,
  });

  return detail;
}

describe("useSelectedPacketDetail", () => {
  it("loads packet detail for selected packet id", async () => {
    const loadPacket = vi.fn(async (packetId: number) => createPacket(packetId));
    const { result } = renderHook(() =>
      useDetailHarness({
        selectedPacketId: 12,
        shouldLoad: true,
        loadPacket,
        initial: null,
      }),
    );

    await waitFor(() => {
      expect(result.current?.id).toBe(12);
    });
    expect(loadPacket).toHaveBeenCalledWith(12, expect.any(AbortSignal));
  });

  it("clears detail when packet selection is empty", async () => {
    const loadPacket = vi.fn(async (packetId: number) => createPacket(packetId));
    const { result } = renderHook(() =>
      useDetailHarness({
        selectedPacketId: null,
        shouldLoad: false,
        loadPacket,
        initial: createPacket(99),
      }),
    );

    await waitFor(() => {
      expect(result.current).toBeNull();
    });
    expect(loadPacket).not.toHaveBeenCalled();
  });

  it("clears detail on non-abort errors", async () => {
    const loadPacket = vi.fn(async () => {
      throw new Error("load failed");
    });
    const { result } = renderHook(() =>
      useDetailHarness({
        selectedPacketId: 18,
        shouldLoad: true,
        loadPacket,
        initial: createPacket(88),
      }),
    );

    await waitFor(() => {
      expect(result.current).toBeNull();
    });
  });
});
