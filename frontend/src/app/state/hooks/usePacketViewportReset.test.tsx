import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { Packet } from "../../core/types";
import { usePacketViewportReset } from "./usePacketViewportReset";

function packet(id: number): Packet {
  return { id, time: "0", src: "a", dst: "b", proto: "TCP", length: 1, info: "", payload: "" } as Packet;
}

describe("usePacketViewportReset", () => {
  it("cancels in-flight page load and resets packet viewport state", () => {
    const cancelPacketPageLoad = vi.fn();
    const { result } = renderHook(() => {
      const hasMorePacketsRef = useRef(true);
      const pageStartRef = useRef(42);
      const [packets, setPackets] = useState<Packet[]>([packet(7)]);
      const [totalPackets, setTotalPackets] = useState(1);
      const [pageStart, setPageStart] = useState(42);
      const [hasPrevPackets, setHasPrevPackets] = useState(true);
      const [hasMorePackets, setHasMorePackets] = useState(true);
      const [selectedPacketId, setSelectedPacketId] = useState<number | null>(7);
      const [selectedPacketDetail, setSelectedPacketDetail] = useState<Packet | null>(packet(7));
      const [selectedPacketRawHex, setSelectedPacketRawHex] = useState("ff");
      const [selectedPacketLayers, setSelectedPacketLayers] = useState<Record<string, unknown> | null>({ frame: {} });
      const resetPacketViewport = usePacketViewportReset({
        cancelPacketPageLoad,
        hasMorePacketsRef,
        pageStartRef,
        setHasMorePackets,
        setHasPrevPackets,
        setPackets,
        setPageStart,
        setSelectedPacketDetail,
        setSelectedPacketId,
        setSelectedPacketLayers,
        setSelectedPacketRawHex,
        setTotalPackets,
      });
      return {
        hasMorePackets,
        hasMorePacketsRef,
        hasPrevPackets,
        packets,
        pageStart,
        pageStartRef,
        resetPacketViewport,
        selectedPacketDetail,
        selectedPacketId,
        selectedPacketLayers,
        selectedPacketRawHex,
        totalPackets,
      };
    });

    act(() => result.current.resetPacketViewport());

    expect(cancelPacketPageLoad).toHaveBeenCalledOnce();
    expect(result.current.pageStartRef.current).toBe(0);
    expect(result.current.hasMorePacketsRef.current).toBe(false);
    expect(result.current.packets).toEqual([]);
    expect(result.current.totalPackets).toBe(0);
    expect(result.current.pageStart).toBe(0);
    expect(result.current.hasPrevPackets).toBe(false);
    expect(result.current.hasMorePackets).toBe(false);
    expect(result.current.selectedPacketId).toBeNull();
    expect(result.current.selectedPacketDetail).toBeNull();
    expect(result.current.selectedPacketRawHex).toBe("");
    expect(result.current.selectedPacketLayers).toBeNull();
  });
});
