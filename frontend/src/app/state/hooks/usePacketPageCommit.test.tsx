import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it } from "vitest";
import type { Packet } from "../../core/types";
import { usePacketPageCommit } from "./usePacketPageCommit";

function packet(id: number): Packet {
  return {
    id,
    time: "0.000000",
    src: "10.0.0.1",
    srcPort: 1234,
    dst: "10.0.0.2",
    dstPort: 80,
    proto: "TCP",
    length: 64,
    info: `packet ${id}`,
    payload: "",
  };
}

describe("usePacketPageCommit", () => {
  it("binds packet page commit state to provider setters", () => {
    const page = { items: [packet(7)], total: 10, hasMore: true };
    const { result } = renderHook(() => {
      const hasMorePacketsRef = useRef(false);
      const pageStartRef = useRef(0);
      const [packets, setPackets] = useState<Packet[]>([]);
      const [pageStart, setPageStart] = useState(0);
      const [totalPackets, setTotalPackets] = useState(0);
      const [selectedPacketId, setSelectedPacketId] = useState<number | null>(7);
      const [selectedPacketDetail, setSelectedPacketDetail] = useState<Packet | null>(packet(7));
      const [selectedPacketRawHex, setSelectedPacketRawHex] = useState("ff");
      const [selectedPacketLayers, setSelectedPacketLayers] = useState<Record<string, unknown> | null>({ frame: {} });
      const [hasPrevPackets, setHasPrevPackets] = useState(false);
      const [hasMorePackets, setHasMorePackets] = useState(false);
      const [packetPageError, setPacketPageError] = useState("old error");
      const commitPacketPage = usePacketPageCommit({
        hasMorePacketsRef,
        pageStartRef,
        setHasMorePackets,
        setHasPrevPackets,
        setPackets,
        setPacketPageError,
        setPageStart,
        setSelectedPacketDetail,
        setSelectedPacketId,
        setSelectedPacketLayers,
        setSelectedPacketRawHex,
        setTotalPackets,
      });
      return {
        commitPacketPage,
        hasMorePackets,
        hasMorePacketsRef,
        hasPrevPackets,
        packetPageError,
        packets,
        pageStart,
        pageStartRef,
        selectedPacketDetail,
        selectedPacketId,
        selectedPacketLayers,
        selectedPacketRawHex,
        totalPackets,
      };
    });

    act(() => {
      result.current.commitPacketPage(5, page);
    });

    expect(result.current.pageStart).toBe(5);
    expect(result.current.pageStartRef.current).toBe(5);
    expect(result.current.totalPackets).toBe(10);
    expect(result.current.packets).toBe(page.items);
    expect(result.current.selectedPacketId).toBe(7);
    expect(result.current.selectedPacketDetail?.id).toBe(7);
    expect(result.current.selectedPacketRawHex).toBe("");
    expect(result.current.selectedPacketLayers).toBeNull();
    expect(result.current.hasPrevPackets).toBe(true);
    expect(result.current.packetPageError).toBe("");
    expect(result.current.hasMorePackets).toBe(true);
    expect(result.current.hasMorePacketsRef.current).toBe(true);
  });
});
