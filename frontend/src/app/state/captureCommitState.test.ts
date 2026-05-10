import { describe, expect, it } from "vitest";
import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../core/types";
import { commitValidatedCaptureState } from "./captureCommitState";
import { EMPTY_SWITCH_METRICS } from "./streamState";
import { createStreamSwitchSequences } from "./streamSwitchSequence";

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
    info: "test packet",
    payload: "",
    rawHex: "",
  };
}

describe("commitValidatedCaptureState", () => {
  it("resets packet and stream runtime, commits capture metadata, and seeds the first page", () => {
    const pageStartRef = { current: 9 };
    const hasMorePacketsRef = { current: false };
    const activeCapturePathRef = { current: "C:/old.pcapng" };
    const httpCache = new Map<number, HttpStream>([
      [1, { id: 1, client: "", server: "", request: "", response: "", chunks: [] }],
    ]);
    const tcpCache = new Map<number, BinaryStream>([[2, { id: 2, protocol: "TCP", from: "", to: "", chunks: [] }]]);
    const udpCache = new Map<number, BinaryStream>([[3, { id: 3, protocol: "UDP", from: "", to: "", chunks: [] }]]);
    const httpPrefetchInFlight = new Set([1]);
    const tcpPrefetchInFlight = new Set([2]);
    const udpPrefetchInFlight = new Set([3]);
    const switchSequences = createStreamSwitchSequences();
    switchSequences.HTTP = 7;
    const switchDurationsRef = { current: { ALL: [1], HTTP: [2], TCP: [3], UDP: [4] } };
    const switchHitsRef = { current: { ALL: 4, HTTP: 1, TCP: 2, UDP: 3 } };
    const firstPage = { items: [createPacket(1)], total: 1, hasMore: false };
    let packets: Packet[] = [createPacket(99)];
    let totalPackets = 99;
    let pageStart = 9;
    let hasPrevPackets = true;
    let hasMorePackets = false;
    let selectedPacketId: number | null = 99;
    let selectedPacketDetail: Packet | null = createPacket(99);
    let selectedPacketRawHex = "ff";
    let selectedPacketLayers: Record<string, unknown> | null = { old: true };
    let streamSwitchMetrics: StreamSwitchMetrics | null = null;
    let analysisResetCount = 0;
    let fileMeta = { name: "", sizeBytes: 0, path: "" };
    let captureRevision = 4;
    const committedPages: Array<{ safeCursor: number; page: typeof firstPage }> = [];

    commitValidatedCaptureState({
      opened: { fileName: "new.pcapng", filePath: "C:/new.pcapng", fileSize: 1234 },
      validatedFirstPage: firstPage,
      pageStartRef,
      hasMorePacketsRef,
      activeCapturePathRef,
      httpCache,
      tcpCache,
      udpCache,
      httpPrefetchInFlight,
      tcpPrefetchInFlight,
      udpPrefetchInFlight,
      switchSequences,
      switchDurationsRef,
      switchHitsRef,
      setPackets: (value) => {
        packets = value as Packet[];
      },
      setTotalPackets: (value) => {
        totalPackets = Number(value);
      },
      setPageStart: (value) => {
        pageStart = Number(value);
      },
      setHasPrevPackets: (value) => {
        hasPrevPackets = Boolean(value);
      },
      setHasMorePackets: (value) => {
        hasMorePackets = Boolean(value);
      },
      setSelectedPacketId: (value) => {
        selectedPacketId = value as number | null;
      },
      setSelectedPacketDetail: (value) => {
        selectedPacketDetail = value as Packet | null;
      },
      setSelectedPacketRawHex: (value) => {
        selectedPacketRawHex = String(value);
      },
      setSelectedPacketLayers: (value) => {
        selectedPacketLayers = value as Record<string, unknown> | null;
      },
      setStreamSwitchMetrics: (value) => {
        streamSwitchMetrics = value as StreamSwitchMetrics;
      },
      resetAnalysisState: () => {
        analysisResetCount += 1;
      },
      setFileMeta: (value) => {
        fileMeta = typeof value === "function" ? value(fileMeta) : value;
      },
      setCaptureRevision: (updater) => {
        captureRevision = typeof updater === "function" ? updater(captureRevision) : Number(updater);
      },
      commitPacketPage: (safeCursor, page) => {
        committedPages.push({ safeCursor, page });
      },
    });

    expect(pageStartRef.current).toBe(0);
    expect(pageStart).toBe(0);
    expect(packets).toEqual([]);
    expect(totalPackets).toBe(0);
    expect(hasPrevPackets).toBe(false);
    expect(hasMorePacketsRef.current).toBe(true);
    expect(hasMorePackets).toBe(true);
    expect(selectedPacketId).toBeNull();
    expect(selectedPacketDetail).toBeNull();
    expect(selectedPacketRawHex).toBe("");
    expect(selectedPacketLayers).toBeNull();
    expect(httpCache.size).toBe(0);
    expect(tcpCache.size).toBe(0);
    expect(udpCache.size).toBe(0);
    expect(httpPrefetchInFlight.size).toBe(0);
    expect(tcpPrefetchInFlight.size).toBe(0);
    expect(udpPrefetchInFlight.size).toBe(0);
    expect(switchSequences).toEqual({ HTTP: 0, TCP: 0, UDP: 0 });
    expect(switchDurationsRef.current).toEqual({ ALL: [], HTTP: [], TCP: [], UDP: [] });
    expect(switchHitsRef.current).toEqual({ ALL: 0, HTTP: 0, TCP: 0, UDP: 0 });
    expect(streamSwitchMetrics).toBe(EMPTY_SWITCH_METRICS);
    expect(analysisResetCount).toBe(1);
    expect(fileMeta).toEqual({ name: "new.pcapng", sizeBytes: 1234, path: "C:/new.pcapng" });
    expect(captureRevision).toBe(5);
    expect(activeCapturePathRef.current).toBe("C:/new.pcapng");
    expect(committedPages).toEqual([{ safeCursor: 0, page: firstPage }]);
  });
});
