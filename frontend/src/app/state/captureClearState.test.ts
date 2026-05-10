import { describe, expect, it } from "vitest";
import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../core/types";
import type { CaptureTransactionStatus } from "./sentinelTypes";
import { clearCaptureUiStateData } from "./captureClearState";
import { EMPTY_BINARY_STREAM, EMPTY_HTTP_STREAM, EMPTY_SWITCH_METRICS } from "./streamState";

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

describe("clearCaptureUiStateData", () => {
  it("clears capture UI, preload, stream runtime, metadata, and active path state", () => {
    const pageStartRef = { current: 5 };
    const hasMorePacketsRef = { current: true };
    const preloadProcessedRef = { current: 20 };
    const preloadTotalRef = { current: 40 };
    const activeCapturePathRef = { current: "C:/capture.pcapng" };
    const httpCache = new Map<number, HttpStream>([
      [1, { id: 1, client: "", server: "", request: "", response: "", chunks: [] }],
    ]);
    const tcpCache = new Map<number, BinaryStream>([[2, { id: 2, protocol: "TCP", from: "", to: "", chunks: [] }]]);
    const udpCache = new Map<number, BinaryStream>([[3, { id: 3, protocol: "UDP", from: "", to: "", chunks: [] }]]);
    const httpPrefetchInFlight = new Set([1]);
    const tcpPrefetchInFlight = new Set([2]);
    const udpPrefetchInFlight = new Set([3]);
    const switchDurationsRef = { current: { ALL: [1], HTTP: [2], TCP: [3], UDP: [4] } };
    const switchHitsRef = { current: { ALL: 4, HTTP: 1, TCP: 2, UDP: 3 } };
    let packets = [createPacket(1)];
    let totalPackets = 1;
    let pageStart = 5;
    let hasPrevPackets = true;
    let hasMorePackets = true;
    let selectedPacketId: number | null = 1;
    let selectedPacketDetail: Packet | null = createPacket(1);
    let selectedPacketRawHex = "ff";
    let selectedPacketLayers: Record<string, unknown> | null = { frame: {} };
    let preloadProcessed = 20;
    let preloadTotal = 40;
    let analysisResetCount = 0;
    let httpStream: HttpStream | null = null;
    let tcpStream: BinaryStream | null = null;
    let udpStream: BinaryStream | null = null;
    let streamIds = { http: [1], tcp: [2], udp: [3] };
    let streamSwitchMetrics: StreamSwitchMetrics | null = null;
    let fileMeta = { name: "capture.pcapng", sizeBytes: 42, path: "C:/capture.pcapng" };
    let packetPageError = "old error";
    let transaction: CaptureTransactionStatus | null = null;
    let captureRevision = 8;

    clearCaptureUiStateData({
      pageStartRef,
      hasMorePacketsRef,
      preloadProcessedRef,
      preloadTotalRef,
      activeCapturePathRef,
      httpCache,
      tcpCache,
      udpCache,
      httpPrefetchInFlight,
      tcpPrefetchInFlight,
      udpPrefetchInFlight,
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
      setPreloadProcessed: (value) => {
        preloadProcessed = Number(value);
      },
      setPreloadTotal: (value) => {
        preloadTotal = Number(value);
      },
      resetAnalysisState: () => {
        analysisResetCount += 1;
      },
      setHttpStream: (value) => {
        httpStream = value as HttpStream;
      },
      setTcpStream: (value) => {
        tcpStream = value as BinaryStream;
      },
      setUdpStream: (value) => {
        udpStream = value as BinaryStream;
      },
      setStreamIds: (value) => {
        streamIds = value as typeof streamIds;
      },
      setStreamSwitchMetrics: (value) => {
        streamSwitchMetrics = value as StreamSwitchMetrics;
      },
      setFileMeta: (value) => {
        fileMeta = typeof value === "function" ? value(fileMeta) : value;
      },
      setPacketPageError: (value) => {
        packetPageError = String(value);
      },
      setCaptureTransaction: (value) => {
        transaction = value as CaptureTransactionStatus;
      },
      setCaptureRevision: (updater) => {
        captureRevision = typeof updater === "function" ? updater(captureRevision) : Number(updater);
      },
    });

    expect(pageStartRef.current).toBe(0);
    expect(hasMorePacketsRef.current).toBe(false);
    expect(preloadProcessedRef.current).toBe(0);
    expect(preloadTotalRef.current).toBe(0);
    expect(activeCapturePathRef.current).toBe("");
    expect(packets).toEqual([]);
    expect(totalPackets).toBe(0);
    expect(pageStart).toBe(0);
    expect(hasPrevPackets).toBe(false);
    expect(hasMorePackets).toBe(false);
    expect(selectedPacketId).toBeNull();
    expect(selectedPacketDetail).toBeNull();
    expect(selectedPacketRawHex).toBe("");
    expect(selectedPacketLayers).toBeNull();
    expect(preloadProcessed).toBe(0);
    expect(preloadTotal).toBe(0);
    expect(analysisResetCount).toBe(1);
    expect(httpStream).toBe(EMPTY_HTTP_STREAM);
    expect(tcpStream).toBe(EMPTY_BINARY_STREAM);
    expect((udpStream as BinaryStream | null)?.protocol).toBe("UDP");
    expect(streamIds).toEqual({ http: [], tcp: [], udp: [] });
    expect(httpCache.size).toBe(0);
    expect(tcpCache.size).toBe(0);
    expect(udpCache.size).toBe(0);
    expect(httpPrefetchInFlight.size).toBe(0);
    expect(tcpPrefetchInFlight.size).toBe(0);
    expect(udpPrefetchInFlight.size).toBe(0);
    expect(switchDurationsRef.current).toEqual({ ALL: [], HTTP: [], TCP: [], UDP: [] });
    expect(switchHitsRef.current).toEqual({ ALL: 0, HTTP: 0, TCP: 0, UDP: 0 });
    expect(streamSwitchMetrics).toBe(EMPTY_SWITCH_METRICS);
    expect(fileMeta).toEqual({ name: "未打开文件", sizeBytes: 0, path: "" });
    expect(packetPageError).toBe("");
    expect(transaction).toMatchObject({ phase: "idle", hasActiveCapture: false });
    expect(captureRevision).toBe(9);
  });
});
