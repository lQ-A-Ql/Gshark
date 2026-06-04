import { describe, expect, it, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useSentinelProviderBody } from "./useSentinelProviderBody";

const noop = vi.fn();
const asyncNoop = vi.fn(async () => undefined);

vi.mock("../integrations/backendClients", () => ({
  backendClients: {
    capture: {
      stopStreamingPackets: vi.fn(),
      prepareCaptureReplacement: vi.fn(),
      getCaptureStatus: vi.fn(),
      openPcapFile: vi.fn(),
      startStreamingPackets: vi.fn(),
      closeCapture: vi.fn(),
    },
    packet: { listPacketsPage: vi.fn() },
    media: { cancelMediaBatchTranscription: vi.fn() },
  },
}));

vi.mock("./hooks/useCapturePreloadState", () => ({
  useCapturePreloadState: () => ({
    isPreloadingCapture: false,
    preloadProcessed: 0,
    preloadTotal: 0,
    preloadProcessedRef: { current: 0 },
    preloadTotalRef: { current: 0 },
    capturePreloadDiagnostics: null,
    setIsPreloadingCapture: noop,
    setPreloadProcessed: noop,
    setPreloadTotal: noop,
    setCapturePreloadDiagnostics: noop,
  }),
}));

vi.mock("./hooks/useCaptureSessionState", () => ({
  useCaptureSessionState: () => ({
    captureTransaction: { phase: "idle", reason: "", message: "", pendingCaptureName: "", pendingCapturePath: "", hasActiveCapture: false },
    setCaptureTransaction: noop,
    fileMeta: null,
    setFileMeta: noop,
    captureRevision: 0,
    setCaptureRevision: noop,
  }),
}));

vi.mock("./hooks/useDisplayFilterState", () => ({
  useDisplayFilterState: () => ({
    displayFilter: "",
    setDisplayFilter: noop,
  }),
}));

vi.mock("./hooks/useSentinelRuntimeRefs", () => ({
  useSentinelRuntimeRefs: () => ({
    activeCapturePathRef: { current: "" },
    captureSeqRef: { current: 0 },
    captureTaskScopeRef: { current: { active: true, id: "test" } },
    filterSeqRef: { current: 0 },
    parseErrorRef: { current: "" },
    parseFinishedRef: { current: false },
    preloadingRef: { current: false },
    refreshAnalysisResultRef: { current: null },
    scheduleLoadMoreRef: { current: null },
    setSelectedPacketIdRef: { current: null },
    threatAnalysisSeqRef: { current: 0 },
    updateProgressFromStatusRef: { current: null },
  }),
}));

vi.mock("./hooks/useAnalysisProgress", () => ({
  useAnalysisProgress: () => ({
    threatHits: [],
    isThreatAnalysisLoading: false,
    setIsThreatAnalysisLoading: noop,
    threatAnalysisProgress: { total: 0, processed: 0, phase: "idle" },
    setThreatAnalysisProgress: noop,
    extractedObjects: [],
    mediaAnalysisProgress: { total: 0, processed: 0, phase: "idle" },
    setMediaAnalysisProgress: noop,
    refreshAnalysisResult: asyncNoop,
    resetAnalysisState: noop,
  }),
}));

vi.mock("./hooks/useRecentCapturesState", () => ({
  useRecentCapturesState: () => ({
    recentCaptures: [],
    rememberRecentCapture: noop,
  }),
}));

vi.mock("./hooks/useCaptureSignalWaiters", () => ({
  useCaptureSignalWaiters: () => ({
    captureWaitersRef: { current: [] },
    wakeCaptureWaiters: noop,
    waitForCaptureSignal: asyncNoop,
  }),
}));

vi.mock("./hooks/useBackendLifecycle", () => ({
  useBackendLifecycle: () => ({
    backendConnected: true,
    backendStatus: "connected",
    setBackendStatus: noop,
    decryptionConfig: {},
    updateDecryptionConfig: noop,
    tsharkStatus: { available: true },
    isTSharkChecking: false,
    toolRuntimeCheckDegraded: false,
    setTSharkPath: asyncNoop,
    toolRuntimeSnapshot: null,
    isToolRuntimeLoading: false,
    refreshToolRuntimeSnapshot: asyncNoop,
    saveToolRuntimeConfig: asyncNoop,
    backendAuthToken: "",
    isBackendAuthTokenLoading: false,
    toolRuntimeProbeState: "idle",
    toolRuntimeProbeTransport: "ipc",
    lastToolRuntimeProbeError: "",
    mcpStatus: null,
    refreshMCPStatus: asyncNoop,
    saveMCPConfig: asyncNoop,
  }),
}));

vi.mock("./hooks/useSentinelPacketStreamBundle", () => ({
  useSentinelPacketStreamBundle: () => ({
    packetPageState: {
      packets: [],
      setPackets: noop,
      totalPackets: 0,
      setTotalPackets: noop,
      setPageStart: noop,
      hasMorePackets: false,
      setHasMorePackets: noop,
      hasPrevPackets: false,
      setHasPrevPackets: noop,
      isPageLoading: false,
      setIsPageLoading: noop,
      isFilterLoading: false,
      setIsFilterLoading: noop,
      packetPageError: "",
      setPacketPageError: noop,
      pageStartRef: { current: 0 },
      packetPageSeqRef: { current: 0 },
      hasMorePacketsRef: { current: false },
      loadMoreScheduledRef: { current: false },
      commitPacketPage: noop,
      resetPacketViewport: noop,
      loadPacketPage: asyncNoop,
      loadMorePackets: asyncNoop,
      loadPrevPackets: asyncNoop,
      jumpToPage: asyncNoop,
      retryPacketPage: asyncNoop,
      locatePacketById: asyncNoop,
      scheduleLoadMore: noop,
      filteredPackets: [],
      selectedPacket: null,
      protocolTree: null,
      hexDump: "",
      currentPage: 0,
      totalPages: 0,
      selectedPacketId: null,
      selectedPacketRawHex: "",
      selectPacket: noop,
      setSelectedPacketId: noop,
      setSelectedPacketDetail: noop,
      setSelectedPacketRawHex: noop,
      setSelectedPacketLayers: noop,
    },
    streamState: {
      httpStream: { items: [], total: 0, page: 0, pageSize: 50 },
      setHttpStream: noop,
      tcpStream: { items: [], total: 0, page: 0, pageSize: 50 },
      setTcpStream: noop,
      udpStream: { items: [], total: 0, page: 0, pageSize: 50 },
      setUdpStream: noop,
      streamIds: { http: null, tcp: null, udp: null },
      setStreamIds: noop,
      httpStreamCacheRef: { current: new Map() },
      tcpStreamCacheRef: { current: new Map() },
      udpStreamCacheRef: { current: new Map() },
      httpPrefetchInFlightRef: { current: false },
      tcpPrefetchInFlightRef: { current: false },
      udpPrefetchInFlightRef: { current: false },
      streamSwitchSequencesRef: { current: { http: 0, tcp: 0, udp: 0 } },
      streamSwitchMetrics: { http: { hit: 0, miss: 0, durationMs: 0 }, tcp: { hit: 0, miss: 0, durationMs: 0 }, udp: { hit: 0, miss: 0, durationMs: 0 } },
      setStreamSwitchMetrics: noop,
      streamSwitchDurationsRef: { current: [] },
      streamSwitchHitsRef: { current: [] },
      refreshStreamIndex: asyncNoop,
      setActiveStream: asyncNoop,
      persistStreamPayloads: asyncNoop,
    },
  }),
}));

vi.mock("./hooks/useFrontendCaptureTaskReset", () => ({
  useFrontendCaptureTaskReset: () => noop,
}));

vi.mock("./hooks/useClearCaptureUiState", () => ({
  useClearCaptureUiState: () => noop,
}));

vi.mock("./hooks/useProgressStatusUpdater", () => ({
  useProgressStatusUpdater: () => noop,
}));

vi.mock("./hooks/useCaptureReplacementPrepare", () => ({
  useCaptureReplacementPrepare: () => noop,
}));

vi.mock("./hooks/useRefreshAnalysisResult", () => ({
  useRefreshAnalysisResult: () => asyncNoop,
}));

vi.mock("./hooks/usePreparePacketStream", () => ({
  usePreparePacketStream: () => asyncNoop,
}));

vi.mock("./hooks/useSyncedRefValue", () => ({
  useSyncedRefValue: () => undefined,
}));

vi.mock("./hooks/useCaptureTaskScopeCleanup", () => ({
  useCaptureTaskScopeCleanup: () => undefined,
}));

vi.mock("./hooks/useCaptureStartWorkflow", () => ({
  useCaptureStartWorkflow: () => asyncNoop,
}));

vi.mock("./hooks/useDisplayFilterWorkflow", () => ({
  useDisplayFilterWorkflow: () => ({
    applyFilter: noop,
    clearFilter: noop,
  }),
}));

vi.mock("./hooks/useOpenCaptureAction", () => ({
  useOpenCaptureAction: () => asyncNoop,
}));

vi.mock("./hooks/useCaptureStopWorkflow", () => ({
  useCaptureStopWorkflow: () => asyncNoop,
}));

describe("useSentinelProviderBody", () => {
  it("TestUseSentinelProviderBodyReturnsAllSubContexts", () => {
    const { result } = renderHook(() => useSentinelProviderBody());

    expect(result.current).toHaveProperty("value");
    expect(result.current).toHaveProperty("backendValue");
    expect(result.current).toHaveProperty("captureValue");
    expect(result.current).toHaveProperty("packetValue");
    expect(result.current).toHaveProperty("streamValue");
    expect(result.current).toHaveProperty("filterValue");
    expect(result.current).toHaveProperty("analysisValue");
  });

  it("TestUseSentinelProviderBodyBackendValue", () => {
    const { result } = renderHook(() => useSentinelProviderBody());
    const { backendValue } = result.current;

    expect(backendValue).toHaveProperty("backendConnected", true);
    expect(backendValue).toHaveProperty("backendStatus", "connected");
    expect(backendValue).toHaveProperty("isTSharkChecking", false);
    expect(backendValue).toHaveProperty("toolRuntimeCheckDegraded", false);
    expect(backendValue).toHaveProperty("isBackendAuthTokenLoading", false);
    expect(backendValue).toHaveProperty("decryptionConfig");
    expect(backendValue).toHaveProperty("mcpStatus", null);
  });

  it("TestUseSentinelProviderBodyCaptureValue", () => {
    const { result } = renderHook(() => useSentinelProviderBody());
    const { captureValue } = result.current;

    expect(captureValue).toHaveProperty("isPreloadingCapture", false);
    expect(captureValue).toHaveProperty("preloadProcessed", 0);
    expect(captureValue).toHaveProperty("preloadTotal", 0);
    expect(captureValue).toHaveProperty("captureRevision", 0);
    expect(captureValue).toHaveProperty("recentCaptures");
    expect(Array.isArray(captureValue.recentCaptures)).toBe(true);
    expect(captureValue).toHaveProperty("captureTransaction");
    expect(captureValue.captureTransaction).toHaveProperty("phase", "idle");
  });

  it("TestUseSentinelProviderBodyPacketValue", () => {
    const { result } = renderHook(() => useSentinelProviderBody());
    const { packetValue } = result.current;

    expect(packetValue).toHaveProperty("packets");
    expect(Array.isArray(packetValue.packets)).toBe(true);
    expect(packetValue).toHaveProperty("totalPackets", 0);
    expect(packetValue).toHaveProperty("currentPage", 0);
    expect(packetValue).toHaveProperty("totalPages", 0);
    expect(packetValue).toHaveProperty("hasMorePackets", false);
    expect(packetValue).toHaveProperty("hasPrevPackets", false);
    expect(packetValue).toHaveProperty("isPageLoading", false);
    expect(packetValue).toHaveProperty("isFilterLoading", false);
    expect(packetValue).toHaveProperty("packetPageError", "");
    expect(packetValue).toHaveProperty("selectedPacket", null);
    expect(packetValue).toHaveProperty("selectedPacketId", null);
  });
});
