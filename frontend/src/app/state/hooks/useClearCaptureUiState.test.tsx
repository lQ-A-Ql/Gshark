import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream } from "../../core/types";
import { useClearCaptureUiState } from "./useClearCaptureUiState";

describe("useClearCaptureUiState", () => {
  it("dereferences stream caches and clears capture UI state", () => {
    const resetAnalysisState = vi.fn();
    const { result } = renderHook(() => {
      const pageStartRef = useRef(4);
      const hasMorePacketsRef = useRef(true);
      const preloadProcessedRef = useRef(8);
      const preloadTotalRef = useRef(9);
      const activeCapturePathRef = useRef("C:/capture.pcap");
      const httpStreamCacheRef = useRef(
        new Map<number, HttpStream>([[1, { id: 1, client: "", server: "", request: "", response: "", chunks: [] }]]),
      );
      const tcpStreamCacheRef = useRef(
        new Map<number, BinaryStream>([[2, { id: 2, protocol: "TCP", from: "", to: "", chunks: [] }]]),
      );
      const udpStreamCacheRef = useRef(
        new Map<number, BinaryStream>([[3, { id: 3, protocol: "UDP", from: "", to: "", chunks: [] }]]),
      );
      const httpPrefetchInFlightRef = useRef(new Set([1]));
      const tcpPrefetchInFlightRef = useRef(new Set([2]));
      const udpPrefetchInFlightRef = useRef(new Set([3]));
      const streamSwitchDurationsRef = useRef({ ALL: [1], HTTP: [2], TCP: [3], UDP: [4] });
      const streamSwitchHitsRef = useRef({ ALL: 4, HTTP: 1, TCP: 2, UDP: 3 });
      const [captureRevision, setCaptureRevision] = useState(0);
      const clearCaptureUiState = useClearCaptureUiState({
        pageStartRef,
        hasMorePacketsRef,
        preloadProcessedRef,
        preloadTotalRef,
        activeCapturePathRef,
        httpStreamCacheRef,
        tcpStreamCacheRef,
        udpStreamCacheRef,
        httpPrefetchInFlightRef,
        tcpPrefetchInFlightRef,
        udpPrefetchInFlightRef,
        streamSwitchDurationsRef,
        streamSwitchHitsRef,
        setPackets: vi.fn(),
        setTotalPackets: vi.fn(),
        setPageStart: vi.fn(),
        setHasPrevPackets: vi.fn(),
        setHasMorePackets: vi.fn(),
        setSelectedPacketId: vi.fn(),
        setSelectedPacketDetail: vi.fn(),
        setSelectedPacketRawHex: vi.fn(),
        setSelectedPacketLayers: vi.fn(),
        setPreloadProcessed: vi.fn(),
        setPreloadTotal: vi.fn(),
        resetAnalysisState,
        setHttpStream: vi.fn(),
        setTcpStream: vi.fn(),
        setUdpStream: vi.fn(),
        setStreamIds: vi.fn(),
        setStreamSwitchMetrics: vi.fn(),
        setFileMeta: vi.fn(),
        setPacketPageError: vi.fn(),
        setCaptureTransaction: vi.fn(),
        setCaptureRevision,
      });
      return {
        clearCaptureUiState,
        activeCapturePathRef,
        httpStreamCacheRef,
        tcpStreamCacheRef,
        udpStreamCacheRef,
        httpPrefetchInFlightRef,
        tcpPrefetchInFlightRef,
        udpPrefetchInFlightRef,
        captureRevision,
      };
    });

    act(() => result.current.clearCaptureUiState());

    expect(result.current.activeCapturePathRef.current).toBe("");
    expect(result.current.httpStreamCacheRef.current.size).toBe(0);
    expect(result.current.tcpStreamCacheRef.current.size).toBe(0);
    expect(result.current.udpStreamCacheRef.current.size).toBe(0);
    expect(result.current.httpPrefetchInFlightRef.current.size).toBe(0);
    expect(result.current.tcpPrefetchInFlightRef.current.size).toBe(0);
    expect(result.current.udpPrefetchInFlightRef.current.size).toBe(0);
    expect(resetAnalysisState).toHaveBeenCalledOnce();
    expect(result.current.captureRevision).toBe(1);
  });
});
