import { describe, expect, it } from "vitest";
import type { Packet } from "../core/types";
import { resetPacketViewportState, resetPreloadCounterState } from "./captureResetState";

describe("captureResetState", () => {
  it("resets packet viewport state and selected packet artifacts", () => {
    const pageStartRef = { current: 42 };
    const hasMorePacketsRef = { current: true };
    let packets: Packet[] = [
      {
        id: 7,
        time: "1.0",
        src: "10.0.0.1",
        srcPort: 12345,
        dst: "10.0.0.2",
        dstPort: 80,
        proto: "TCP",
        length: 60,
        info: "test",
        payload: "",
      },
    ];
    let totalPackets = 1;
    let pageStart = 42;
    let hasPrevPackets = true;
    let hasMorePackets = true;
    let selectedPacketId: number | null = 7;
    let selectedPacketDetail: Packet | null = packets[0] ?? null;
    let selectedPacketRawHex = "abcd";
    let selectedPacketLayers: Record<string, unknown> | null = { tcp: {} };

    resetPacketViewportState({
      pageStartRef,
      hasMorePacketsRef,
      setPackets: (value) => {
        packets = typeof value === "function" ? value(packets) : value;
      },
      setTotalPackets: (value) => {
        totalPackets = typeof value === "function" ? value(totalPackets) : value;
      },
      setPageStart: (value) => {
        pageStart = typeof value === "function" ? value(pageStart) : value;
      },
      setHasPrevPackets: (value) => {
        hasPrevPackets = typeof value === "function" ? value(hasPrevPackets) : value;
      },
      setHasMorePackets: (value) => {
        hasMorePackets = typeof value === "function" ? value(hasMorePackets) : value;
      },
      setSelectedPacketId: (value) => {
        selectedPacketId = typeof value === "function" ? value(selectedPacketId) : value;
      },
      setSelectedPacketDetail: (value) => {
        selectedPacketDetail = typeof value === "function" ? value(selectedPacketDetail) : value;
      },
      setSelectedPacketRawHex: (value) => {
        selectedPacketRawHex = typeof value === "function" ? value(selectedPacketRawHex) : value;
      },
      setSelectedPacketLayers: (value) => {
        selectedPacketLayers = typeof value === "function" ? value(selectedPacketLayers) : value;
      },
    });

    expect(pageStartRef.current).toBe(0);
    expect(hasMorePacketsRef.current).toBe(false);
    expect(packets).toEqual([]);
    expect(totalPackets).toBe(0);
    expect(pageStart).toBe(0);
    expect(hasPrevPackets).toBe(false);
    expect(hasMorePackets).toBe(false);
    expect(selectedPacketId).toBeNull();
    expect(selectedPacketDetail).toBeNull();
    expect(selectedPacketRawHex).toBe("");
    expect(selectedPacketLayers).toBeNull();
  });

  it("can reset packet viewport while marking more packets expected", () => {
    const pageStartRef = { current: 5 };
    const hasMorePacketsRef = { current: false };
    let hasMorePackets = false;

    resetPacketViewportState({
      pageStartRef,
      hasMorePacketsRef,
      setPackets: () => undefined,
      setTotalPackets: () => undefined,
      setPageStart: () => undefined,
      setHasPrevPackets: () => undefined,
      setHasMorePackets: (value) => {
        hasMorePackets = typeof value === "function" ? value(hasMorePackets) : value;
      },
      setSelectedPacketId: () => undefined,
      setSelectedPacketDetail: () => undefined,
      setSelectedPacketRawHex: () => undefined,
      setSelectedPacketLayers: () => undefined,
      hasMorePackets: true,
    });

    expect(pageStartRef.current).toBe(0);
    expect(hasMorePacketsRef.current).toBe(true);
    expect(hasMorePackets).toBe(true);
  });

  it("resets preload counters and refs together", () => {
    const preloadProcessedRef = { current: 12 };
    const preloadTotalRef = { current: 24 };
    let preloadProcessed = 12;
    let preloadTotal = 24;

    resetPreloadCounterState({
      preloadProcessedRef,
      preloadTotalRef,
      setPreloadProcessed: (value) => {
        preloadProcessed = typeof value === "function" ? value(preloadProcessed) : value;
      },
      setPreloadTotal: (value) => {
        preloadTotal = typeof value === "function" ? value(preloadTotal) : value;
      },
    });

    expect(preloadProcessedRef.current).toBe(0);
    expect(preloadTotalRef.current).toBe(0);
    expect(preloadProcessed).toBe(0);
    expect(preloadTotal).toBe(0);
  });
});
