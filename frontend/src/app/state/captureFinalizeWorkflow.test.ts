import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../core/types";
import { finalizeOpenedCapture } from "./captureFinalizeWorkflow";
import { createStreamSwitchSequences } from "./streamSwitchSequence";

const opened = { fileName: "sample.pcapng", filePath: "C:/captures/sample.pcapng", fileSize: 42 };
const packet = { id: 1, proto: "TCP" } as Packet;
const firstPage = { items: [packet], total: 1, hasMore: false };

function createOptions(overrides: Partial<Parameters<typeof finalizeOpenedCapture>[0]> = {}) {
  return {
    opened,
    validatedFirstPage: firstPage,
    captureSeq: 1,
    captureSeqRef: { current: 1 },
    pageStartRef: { current: 10 },
    hasMorePacketsRef: { current: false },
    activeCapturePathRef: { current: "C:/old.pcapng" },
    httpCache: new Map<number, HttpStream>([
      [1, { id: 1, client: "", server: "", request: "", response: "", chunks: [] }],
    ]),
    tcpCache: new Map<number, BinaryStream>([[2, { id: 2, protocol: "TCP", from: "", to: "", chunks: [] }]]),
    udpCache: new Map<number, BinaryStream>([[3, { id: 3, protocol: "UDP", from: "", to: "", chunks: [] }]]),
    httpPrefetchInFlight: new Set([1]),
    tcpPrefetchInFlight: new Set([2]),
    udpPrefetchInFlight: new Set([3]),
    switchSequences: createStreamSwitchSequences(),
    switchDurationsRef: { current: { ALL: [1], HTTP: [1], TCP: [], UDP: [] } },
    switchHitsRef: { current: { ALL: 1, HTTP: 1, TCP: 0, UDP: 0 } },
    setPackets: vi.fn(),
    setTotalPackets: vi.fn(),
    setPageStart: vi.fn(),
    setHasPrevPackets: vi.fn(),
    setHasMorePackets: vi.fn(),
    setSelectedPacketId: vi.fn(),
    setSelectedPacketDetail: vi.fn(),
    setSelectedPacketRawHex: vi.fn(),
    setSelectedPacketLayers: vi.fn(),
    setStreamSwitchMetrics: vi.fn(
      (_value: StreamSwitchMetrics | ((prev: StreamSwitchMetrics) => StreamSwitchMetrics)) => undefined,
    ),
    resetAnalysisState: vi.fn(),
    setFileMeta: vi.fn(),
    setCaptureRevision: vi.fn(),
    commitPacketPage: vi.fn(),
    refreshStreamIndex: vi.fn(async () => undefined),
    setCaptureTransaction: vi.fn(),
    setBackendStatus: vi.fn(),
    refreshAnalysisResult: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("captureFinalizeWorkflow", () => {
  it("commits capture state, refreshes streams, and announces a completed preload", async () => {
    const options = createOptions();

    await expect(finalizeOpenedCapture(options)).resolves.toBe(true);

    expect(options.commitPacketPage).toHaveBeenCalledWith(0, firstPage);
    expect(options.refreshStreamIndex).toHaveBeenCalledTimes(1);
    expect(options.activeCapturePathRef.current).toBe(opened.filePath);
    expect(options.setCaptureTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ phase: "idle", hasActiveCapture: true }),
    );
    expect(options.setBackendStatus).toHaveBeenCalledWith("预加载完成，可浏览全部流量: sample.pcapng");
    expect(options.refreshAnalysisResult).toHaveBeenCalledWith({
      capturePath: opened.filePath,
      quietSuccess: true,
    });
  });

  it("keeps stale capture finalization from publishing done status or analysis refresh", async () => {
    const captureSeqRef = { current: 1 };
    const options = createOptions({
      captureSeqRef,
      refreshStreamIndex: vi.fn(async () => {
        captureSeqRef.current = 2;
      }),
    });

    await expect(finalizeOpenedCapture(options)).resolves.toBe(false);

    expect(options.setCaptureTransaction).not.toHaveBeenCalled();
    expect(options.setBackendStatus).not.toHaveBeenCalledWith("预加载完成，可浏览全部流量: sample.pcapng");
    expect(options.refreshAnalysisResult).not.toHaveBeenCalled();
  });
});
