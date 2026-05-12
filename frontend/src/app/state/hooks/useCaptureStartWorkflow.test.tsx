import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { BinaryStream, HttpStream, Packet, StreamSwitchMetrics } from "../../core/types";
import { createCaptureTaskScope } from "../../utils/captureTaskScope";
import { createInitialCaptureFileMeta } from "../captureOpenState";
import { createIdleCaptureTransactionStatus } from "../captureTransactionStatus";
import { EMPTY_SWITCH_METRICS } from "../streamState";
import { createStreamSwitchSequences } from "../streamSwitchSequence";
import { useCaptureStartWorkflow } from "./useCaptureStartWorkflow";

const packet = { id: 1, proto: "TCP", src: "10.0.0.1", dst: "10.0.0.2", length: 54 } as Packet;
const opened = { fileName: "sample.pcapng", filePath: "C:/captures/sample.pcapng", fileSize: 42 };

describe("useCaptureStartWorkflow", () => {
  it("opens, preloads, finalizes capture state, and schedules analysis refresh", async () => {
    const prepareForCaptureReplacement = vi.fn(async () => undefined);
    const startStreamingPackets = vi.fn(async () => undefined);
    const listPacketsPage = vi.fn(async () => ({
      items: [packet],
      nextCursor: 1,
      total: 1,
      hasMore: false,
    }));
    const getCaptureStatus = vi.fn(async () => ({
      filePath: opened.filePath,
      hasCapture: true,
      packetCount: 1,
    }));
    const refreshStreamIndex = vi.fn(async () => undefined);
    const refreshAnalysisResult = vi.fn(async () => undefined);
    const rememberRecentCapture = vi.fn();
    const resetAnalysisState = vi.fn();
    const wakeCaptureWaiters = vi.fn();

    const { result } = renderHook(() => {
      const [packets, setPackets] = useState<Packet[]>([]);
      const [totalPackets, setTotalPackets] = useState(0);
      const [backendStatus, setBackendStatus] = useState("");
      const [captureTransaction, setCaptureTransaction] = useState(createIdleCaptureTransactionStatus(false));
      const [fileMeta, setFileMeta] = useState(createInitialCaptureFileMeta);
      const [, setStreamSwitchMetrics] = useState<StreamSwitchMetrics>(EMPTY_SWITCH_METRICS);

      const startCapture = useCaptureStartWorkflow({
        backendConnected: true,
        displayFilter: "",
        activeCapturePathRef: useRef(""),
        captureSeqRef: useRef(0),
        captureTaskScopeRef: useRef(createCaptureTaskScope()),
        filterSeqRef: useRef(0),
        hasMorePacketsRef: useRef(false),
        httpCacheRef: useRef(new Map<number, HttpStream>()),
        httpPrefetchInFlightRef: useRef(new Set<number>()),
        pageStartRef: useRef(0),
        parseErrorRef: useRef(""),
        parseFinishedRef: useRef(false),
        preloadingRef: useRef(false),
        preloadProcessedRef: useRef(0),
        preloadTotalRef: useRef(0),
        streamSwitchDurationsRef: useRef({ ALL: [], HTTP: [], TCP: [], UDP: [] }),
        streamSwitchHitsRef: useRef({ ALL: 0, HTTP: 0, TCP: 0, UDP: 0 }),
        streamSwitchSequencesRef: useRef(createStreamSwitchSequences()),
        tcpCacheRef: useRef(new Map<number, BinaryStream>()),
        tcpPrefetchInFlightRef: useRef(new Set<number>()),
        udpCacheRef: useRef(new Map<number, BinaryStream>()),
        udpPrefetchInFlightRef: useRef(new Set<number>()),
        commitPacketPage: (safeCursor, page) => {
          setPackets(page.items);
          setTotalPackets(page.total);
          expect(safeCursor).toBe(0);
        },
        getCaptureStatus,
        listPacketsPage,
        openPcapFile: vi.fn(async () => opened),
        prepareForCaptureReplacement,
        refreshAnalysisResult,
        refreshStreamIndex,
        rememberRecentCapture,
        resetAnalysisState,
        setBackendStatus,
        setCaptureRevision: vi.fn(),
        setCaptureTransaction,
        setFileMeta,
        setHasMorePackets: vi.fn(),
        setHasPrevPackets: vi.fn(),
        setIsFilterLoading: vi.fn(),
        setIsPreloadingCapture: vi.fn(),
        setPacketPageError: vi.fn(),
        setPackets,
        setPageStart: vi.fn(),
        setPreloadProcessed: vi.fn(),
        setPreloadTotal: vi.fn(),
        setSelectedPacketDetail: vi.fn(),
        setSelectedPacketId: vi.fn(),
        setSelectedPacketLayers: vi.fn(),
        setSelectedPacketRawHex: vi.fn(),
        setStreamSwitchMetrics,
        setTotalPackets,
        startStreamingPackets,
        waitForCaptureSignal: vi.fn(async () => undefined),
        wakeCaptureWaiters,
      });

      return { backendStatus, captureTransaction, fileMeta, packets, startCapture, totalPackets };
    });

    await act(async () => {
      await expect(result.current.startCapture(opened.filePath, "")).resolves.toBe(true);
    });

    expect(prepareForCaptureReplacement).toHaveBeenCalledTimes(1);
    expect(startStreamingPackets).toHaveBeenCalledWith(opened.filePath, "", expect.any(AbortSignal));
    expect(listPacketsPage).toHaveBeenCalledWith(0, 2000, "", expect.any(AbortSignal));
    expect(refreshStreamIndex).toHaveBeenCalledTimes(1);
    expect(refreshAnalysisResult).toHaveBeenCalledWith({
      capturePath: opened.filePath,
      quietSuccess: true,
    });
    expect(result.current.packets).toEqual([packet]);
    expect(result.current.totalPackets).toBe(1);
    expect(result.current.fileMeta).toMatchObject({ path: opened.filePath, name: opened.fileName });
    expect(result.current.captureTransaction).toMatchObject({ phase: "idle", hasActiveCapture: true });
    expect(result.current.backendStatus).toBe("预加载完成，可浏览全部流量: sample.pcapng");
    expect(rememberRecentCapture).toHaveBeenCalledTimes(1);
    expect(resetAnalysisState).toHaveBeenCalledTimes(1);
    expect(wakeCaptureWaiters).toHaveBeenCalledTimes(1);
  });
});
