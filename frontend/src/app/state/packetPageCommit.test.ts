import { describe, expect, it } from "vitest";
import type { Packet } from "../core/types";
import { commitPacketPageState } from "./packetPageCommit";

function createPacket(id: number): Packet {
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

describe("commitPacketPageState", () => {
  it("commits packet page state and keeps selected packet when it remains visible", () => {
    const pageStartRef = { current: 0 };
    const hasMorePacketsRef = { current: false };
    const page = { items: [createPacket(7), createPacket(8)], total: 10, hasMore: true };
    let pageStart = 0;
    let totalPackets = 0;
    let packets: Packet[] = [];
    let selectedPacketId: number | null = 7;
    let selectedPacketDetail: Packet | null = createPacket(7);
    let selectedPacketRawHex = "ff";
    let selectedPacketLayers: Record<string, unknown> | null = { frame: {} };
    let hasPrevPackets = false;
    let packetPageError = "old error";
    let hasMorePackets = false;

    commitPacketPageState({
      safeCursor: 5,
      page,
      pageStartRef,
      hasMorePacketsRef,
      setPageStart: (value) => {
        pageStart = Number(value);
      },
      setTotalPackets: (value) => {
        totalPackets = Number(value);
      },
      setPackets: (value) => {
        packets = value as Packet[];
      },
      setSelectedPacketId: (value) => {
        selectedPacketId = typeof value === "function" ? value(selectedPacketId) : value;
      },
      setSelectedPacketDetail: (value) => {
        selectedPacketDetail = typeof value === "function" ? value(selectedPacketDetail) : value;
      },
      setSelectedPacketRawHex: (value) => {
        selectedPacketRawHex = String(value);
      },
      setSelectedPacketLayers: (value) => {
        selectedPacketLayers = value as Record<string, unknown> | null;
      },
      setHasPrevPackets: (value) => {
        hasPrevPackets = Boolean(value);
      },
      setPacketPageError: (value) => {
        packetPageError = String(value);
      },
      setHasMorePackets: (value) => {
        hasMorePackets = Boolean(value);
      },
    });

    expect(pageStartRef.current).toBe(5);
    expect(pageStart).toBe(5);
    expect(totalPackets).toBe(10);
    expect(packets).toBe(page.items);
    expect(selectedPacketId).toBe(7);
    expect(selectedPacketDetail?.id).toBe(7);
    expect(selectedPacketRawHex).toBe("");
    expect(selectedPacketLayers).toBeNull();
    expect(hasPrevPackets).toBe(true);
    expect(packetPageError).toBe("");
    expect(hasMorePacketsRef.current).toBe(true);
    expect(hasMorePackets).toBe(true);
  });

  it("clears selected packet state when the packet leaves the committed page", () => {
    let selectedPacketId: number | null = 99;
    let selectedPacketDetail: Packet | null = createPacket(99);

    commitPacketPageState({
      safeCursor: 0,
      page: { items: [createPacket(1)], total: 1, hasMore: false },
      pageStartRef: { current: 2 },
      hasMorePacketsRef: { current: true },
      setPageStart: () => {},
      setTotalPackets: () => {},
      setPackets: () => {},
      setSelectedPacketId: (value) => {
        selectedPacketId = typeof value === "function" ? value(selectedPacketId) : value;
      },
      setSelectedPacketDetail: (value) => {
        selectedPacketDetail = typeof value === "function" ? value(selectedPacketDetail) : value;
      },
      setSelectedPacketRawHex: () => {},
      setSelectedPacketLayers: () => {},
      setHasPrevPackets: () => {},
      setPacketPageError: () => {},
      setHasMorePackets: () => {},
    });

    expect(selectedPacketId).toBeNull();
    expect(selectedPacketDetail).toBeNull();
  });
});
