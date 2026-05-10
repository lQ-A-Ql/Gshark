import {
  createContext,
  startTransition,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type PropsWithChildren,
} from "react";
import type { BinaryStream, HttpStream, Packet } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { isAbortLikeError } from "../utils/asyncControl";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { useBackendLifecycle } from "./hooks/useBackendLifecycle";
import { useSelectedPacketResources } from "./hooks/useSelectedPacketResources";
import { useSyncedRefValue } from "./hooks/useSyncedRefValue";
import { useAnalysisProgress } from "./hooks/useAnalysisProgress";
import { getCaptureOpenDisconnectedStatus } from "./capturePreloadStatus";
import { buildOpenedCaptureFromPath, createInitialCaptureFileMeta } from "./captureOpenState";
import { prepareAndStartOpenedCapture, resolveOpenedCapture } from "./captureStartBackend";
import { buildFailedCaptureTransactionStatus, createIdleCaptureTransactionStatus } from "./captureTransactionStatus";
import { stopCapturePreloading } from "./captureParseRuntimeState";
import { resetPacketViewportState } from "./captureResetState";
import { finalizeOpenedCapture } from "./captureFinalizeWorkflow";
import { clearCaptureUiStateData } from "./captureClearState";
import { cancelFrontendCaptureTasks } from "./captureTaskReset";
import { loadPacketPageState } from "./packetPageLoad";
import { commitPacketPageState } from "./packetPageCommit";
import {
  jumpToPacketPage,
  loadNextPacketPage,
  loadPreviousPacketPage,
  retryPacketPageLoad,
} from "./packetPageNavigation";
import { runPacketFilterAction } from "./packetFilterAction";
import { locatePacketByIdWorkflow } from "./packetLocateWorkflow";
import { preparePacketStreamState } from "./packetStreamPrepare";
import { PAGE_SIZE, RAW_STREAM_PAGE_SIZE, STREAM_PREFETCH_LIMIT } from "./captureConstants";
import { EMPTY_BINARY_STREAM, EMPTY_HTTP_STREAM, createEmptyStreamIds, createEmptyUdpStream } from "./streamState";
import { refreshStreamIndexState } from "./streamIndexRefresh";
import { persistStreamPayloadsState } from "./streamPayloadPersist";
import { updateProgressFromStatusState } from "./progressStatusWorkflow";
import { prefetchAdjacentStreamsState } from "./streamAdjacentPrefetch";
import { createStreamSwitchSequences } from "./streamSwitchSequence";
import { setActiveStreamState } from "./streamSwitchWorkflow";
import { prepareCaptureReplacementState } from "./captureReplacementPrepare";
import { stopCaptureWorkflow } from "./captureStopWorkflow";
import { resolveCapturePreloadFirstPage } from "./capturePreloadProbe";
import { buildSentinelDerivedView } from "./sentinelDerivedView";
import type { PreparedPacketStream, SentinelContextValue } from "./sentinelTypes";
import { useStreamSwitchMetrics } from "./hooks/useStreamSwitchMetrics";
import { useCaptureSignalWaiters } from "./hooks/useCaptureSignalWaiters";
import { useRecentCapturesState } from "./hooks/useRecentCapturesState";
import { useSelectedPacketAction } from "./hooks/useSelectedPacketAction";
import { usePacketPageCancellation } from "./hooks/usePacketPageCancellation";

const SentinelContext = createContext<SentinelContextValue | null>(null);

export function SentinelProvider({ children }: PropsWithChildren) {
  const [packets, setPackets] = useState<Packet[]>([]);
  const [totalPackets, setTotalPackets] = useState(0);
  const [pageStart, setPageStart] = useState(0);
  const [isPreloadingCapture, setIsPreloadingCapture] = useState(false);
  const [preloadProcessed, setPreloadProcessed] = useState(0);
  const [preloadTotal, setPreloadTotal] = useState(0);
  const [hasMorePackets, setHasMorePackets] = useState(false);
  const [hasPrevPackets, setHasPrevPackets] = useState(false);
  const [isPageLoading, setIsPageLoading] = useState(false);
  const [isFilterLoading, setIsFilterLoading] = useState(false);
  const [packetPageError, setPacketPageError] = useState("");
  const [captureTransaction, setCaptureTransaction] = useState(createIdleCaptureTransactionStatus(false));
  const [displayFilter, setDisplayFilter] = useState("");
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [selectedPacketDetail, setSelectedPacketDetail] = useState<Packet | null>(null);
  const [selectedPacketRawHex, setSelectedPacketRawHex] = useState("");
  const [selectedPacketLayers, setSelectedPacketLayers] = useState<Record<string, unknown> | null>(null);
  const threatAnalysisSeqRef = useRef(0);
  const {
    threatHits,
    isThreatAnalysisLoading,
    setIsThreatAnalysisLoading,
    threatAnalysisProgress,
    setThreatAnalysisProgress,
    extractedObjects,
    mediaAnalysisProgress,
    setMediaAnalysisProgress,
    refreshAnalysisResult: refreshAnalysisResultImpl,
    resetAnalysisState,
  } = useAnalysisProgress(threatAnalysisSeqRef);
  const [httpStream, setHttpStream] = useState<HttpStream>(EMPTY_HTTP_STREAM);
  const [tcpStream, setTcpStream] = useState<BinaryStream>(EMPTY_BINARY_STREAM);
  const [udpStream, setUdpStream] = useState<BinaryStream>(createEmptyUdpStream);
  const [streamIds, setStreamIds] = useState(createEmptyStreamIds);
  const [fileMeta, setFileMeta] = useState(createInitialCaptureFileMeta);
  const [captureRevision, setCaptureRevision] = useState(0);
  const { recentCaptures, rememberRecentCapture } = useRecentCapturesState();

  const pageStartRef = useRef(0);
  const captureTaskScopeRef = useRef(createCaptureTaskScope());
  const packetPageSeqRef = useRef(0);
  const hasMorePacketsRef = useRef(false);
  const loadMoreScheduledRef = useRef<number | null>(null);
  const parseFinishedRef = useRef(false);
  const parseErrorRef = useRef("");
  const preloadingRef = useRef(false);
  const captureSeqRef = useRef(0);
  const filterSeqRef = useRef(0);
  const { captureWaitersRef, wakeCaptureWaiters, waitForCaptureSignal } = useCaptureSignalWaiters();
  const preloadProcessedRef = useRef(0);
  const preloadTotalRef = useRef(0);
  const activeCapturePathRef = useRef("");
  const httpStreamCacheRef = useRef<Map<number, HttpStream>>(new Map());
  const tcpStreamCacheRef = useRef<Map<number, BinaryStream>>(new Map());
  const udpStreamCacheRef = useRef<Map<number, BinaryStream>>(new Map());
  const scheduleLoadMoreRef = useRef<() => void>(() => undefined);
  const refreshAnalysisResultRef = useRef<
    (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>
  >(async () => {});
  const updateProgressFromStatusRef = useRef<(message: string) => boolean>(() => false);
  const httpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const tcpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const udpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const streamSwitchSequencesRef = useRef(createStreamSwitchSequences());
  const {
    streamSwitchMetrics,
    setStreamSwitchMetrics,
    streamSwitchDurationsRef,
    streamSwitchHitsRef,
    recordStreamSwitchMetric,
  } = useStreamSwitchMetrics();
  const {
    backendConnected,
    backendStatus,
    setBackendStatus,
    decryptionConfig,
    updateDecryptionConfig,
    tsharkStatus,
    isTSharkChecking,
    toolRuntimeCheckDegraded,
    setTSharkPath,
    toolRuntimeSnapshot,
    isToolRuntimeLoading,
    refreshToolRuntimeSnapshot,
    saveToolRuntimeConfig,
  } = useBackendLifecycle({
    activeCapturePathRef,
    captureWaitersRef,
    parseFinishedRef,
    parseErrorRef,
    preloadingRef,
    scheduleLoadMoreRef,
    refreshAnalysisResultRef,
    updateProgressFromStatusRef,
    setSelectedPacketId,
    setMediaAnalysisProgress,
    setThreatAnalysisProgress,
    setIsThreatAnalysisLoading,
  });

  const cancelAllFrontendCaptureTasks = useCallback(() => {
    cancelFrontendCaptureTasks({
      captureTaskScopeRef,
      packetPageSeqRef,
      threatAnalysisSeqRef,
      streamSwitchSequences: streamSwitchSequencesRef.current,
      httpPrefetchInFlight: httpPrefetchInFlightRef.current,
      tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
      udpPrefetchInFlight: udpPrefetchInFlightRef.current,
      loadMoreScheduledRef,
      clearScheduledLoadMore: window.clearTimeout,
      setIsPageLoading,
      setPacketPageError,
    });
  }, []);

  const cancelPacketPageLoad = usePacketPageCancellation({
    captureTaskScopeRef,
    packetPageSeqRef,
    setIsPageLoading,
  });

  const commitPacketPage = useCallback(
    (safeCursor: number, page: { items: Packet[]; total: number; hasMore: boolean }) => {
      commitPacketPageState({
        safeCursor,
        page,
        pageStartRef,
        hasMorePacketsRef,
        setPageStart,
        setTotalPackets,
        setPackets,
        setSelectedPacketId,
        setSelectedPacketDetail,
        setSelectedPacketRawHex,
        setSelectedPacketLayers,
        setHasPrevPackets,
        setPacketPageError,
        setHasMorePackets,
      });
    },
    [],
  );

  const resetPacketViewport = useCallback(() => {
    cancelPacketPageLoad();
    resetPacketViewportState({
      pageStartRef,
      hasMorePacketsRef,
      setPackets,
      setTotalPackets,
      setPageStart,
      setHasPrevPackets,
      setHasMorePackets,
      setSelectedPacketId,
      setSelectedPacketDetail,
      setSelectedPacketRawHex,
      setSelectedPacketLayers,
    });
  }, [cancelPacketPageLoad]);

  const clearCaptureUiState = useCallback(() => {
    clearCaptureUiStateData({
      pageStartRef,
      hasMorePacketsRef,
      preloadProcessedRef,
      preloadTotalRef,
      activeCapturePathRef,
      httpCache: httpStreamCacheRef.current,
      tcpCache: tcpStreamCacheRef.current,
      udpCache: udpStreamCacheRef.current,
      httpPrefetchInFlight: httpPrefetchInFlightRef.current,
      tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
      udpPrefetchInFlight: udpPrefetchInFlightRef.current,
      switchDurationsRef: streamSwitchDurationsRef,
      switchHitsRef: streamSwitchHitsRef,
      setPackets,
      setTotalPackets,
      setPageStart,
      setHasPrevPackets,
      setHasMorePackets,
      setSelectedPacketId,
      setSelectedPacketDetail,
      setSelectedPacketRawHex,
      setSelectedPacketLayers,
      setPreloadProcessed,
      setPreloadTotal,
      resetAnalysisState,
      setHttpStream,
      setTcpStream,
      setUdpStream,
      setStreamIds,
      setStreamSwitchMetrics,
      setFileMeta,
      setPacketPageError,
      setCaptureTransaction,
      setCaptureRevision,
    });
  }, [resetAnalysisState]);

  const loadPacketPage = useCallback(
    async (cursor: number, filterOverride?: string, options?: { finishFilterLoading?: boolean }) => {
      return loadPacketPageState({
        cursor,
        pageSize: PAGE_SIZE,
        filter: filterOverride ?? displayFilter,
        activeCapturePathRef,
        backendConnected,
        packetPageSeqRef,
        captureTaskScopeRef,
        listPacketsPage: bridge.listPacketsPage,
        commitPacketPage,
        setIsPageLoading,
        setIsFilterLoading,
        setPacketPageError,
        setBackendStatus,
        finishFilterLoading: options?.finishFilterLoading,
      });
    },
    [backendConnected, commitPacketPage, displayFilter],
  );

  const loadMorePackets = useCallback(async () => {
    await loadNextPacketPage({ pageStartRef, pageSize: PAGE_SIZE, loadPacketPage });
  }, [loadPacketPage]);

  const loadPrevPackets = useCallback(async () => {
    await loadPreviousPacketPage({ pageStartRef, pageSize: PAGE_SIZE, loadPacketPage });
  }, [loadPacketPage]);

  const jumpToPage = useCallback(
    async (page: number) => {
      await jumpToPacketPage({ page, totalPackets, pageSize: PAGE_SIZE, loadPacketPage });
    },
    [loadPacketPage, totalPackets],
  );

  const retryPacketPage = useCallback(async () => {
    await retryPacketPageLoad({ pageStartRef, displayFilter, loadPacketPage, setBackendStatus });
  }, [displayFilter, loadPacketPage, setBackendStatus]);

  const locatePacketById = useCallback(
    async (packetId: number, filterOverride?: string) => {
      return locatePacketByIdWorkflow({
        packetId,
        pageSize: PAGE_SIZE,
        filterOverride,
        displayFilter,
        activeCapturePathRef,
        captureTaskScopeRef,
        locatePacketPage: bridge.locatePacketPage,
        loadPacketPage,
        setDisplayFilter,
        setSelectedPacketId,
        setBackendStatus,
      });
    },
    [displayFilter, loadPacketPage],
  );

  const scheduleLoadMore = useCallback(
    (delayMs = 120) => {
      if (loadMoreScheduledRef.current != null) return;
      loadMoreScheduledRef.current = window.setTimeout(() => {
        loadMoreScheduledRef.current = null;
        void loadPacketPage(pageStartRef.current);
      }, delayMs);
    },
    [loadPacketPage],
  );

  const updateProgressFromStatus = useCallback((message: string): boolean => {
    return updateProgressFromStatusState({
      message,
      preloadProcessedRef,
      preloadTotalRef,
      setPreloadProcessed,
      setPreloadTotal,
      setTotalPackets,
      setMediaAnalysisProgress,
      setThreatAnalysisProgress,
    });
  }, []);

  const prepareForCaptureReplacement = useCallback(async () => {
    await prepareCaptureReplacementState({
      backendConnected,
      parseFinishedRef,
      parseErrorRef,
      preloadingRef,
      preloadProcessedRef,
      preloadTotalRef,
      cancelAllFrontendCaptureTasks,
      wakeCaptureWaiters,
      setIsPreloadingCapture,
      setIsFilterLoading,
      setPreloadProcessed,
      setPreloadTotal,
      stopStreamingPackets: bridge.stopStreamingPackets,
      prepareCaptureReplacement: bridge.prepareCaptureReplacement,
    });
  }, [backendConnected, cancelAllFrontendCaptureTasks, wakeCaptureWaiters]);

  useEffect(() => {
    hasMorePacketsRef.current = hasMorePackets;
  }, [hasMorePackets]);

  const { filteredPackets, selectedPacket, protocolTree, hexDump, currentPage, totalPages } = useMemo(
    () =>
      buildSentinelDerivedView({
        packets,
        selectedPacketId,
        selectedPacketDetail,
        selectedPacketLayers,
        pageStart,
        totalPackets,
        pageSize: PAGE_SIZE,
      }),
    [packets, pageStart, selectedPacketDetail, selectedPacketId, selectedPacketLayers, totalPackets],
  );

  const refreshAnalysisResult = useCallback(
    async (options?: { capturePath?: string; quietSuccess?: boolean }) => {
      await refreshAnalysisResultImpl({
        ...options,
        backendConnected,
        activeCapturePath: activeCapturePathRef.current,
        captureTaskScope: captureTaskScopeRef.current,
        setBackendStatus,
      });
    },
    [refreshAnalysisResultImpl, backendConnected],
  );

  const refreshStreamIndex = useCallback(async () => {
    await refreshStreamIndexState({
      backendConnected,
      activeCapturePathRef,
      captureTaskScopeRef,
      listStreamIds: bridge.listStreamIds,
      setStreamIds,
      setBackendStatus,
    });
  }, [backendConnected]);

  const prefetchAdjacentStreams = useCallback(
    (protocol: "HTTP" | "TCP" | "UDP", currentStreamId: number) => {
      prefetchAdjacentStreamsState({
        backendConnected,
        activeCapturePath: activeCapturePathRef.current,
        protocol,
        currentStreamId,
        limit: STREAM_PREFETCH_LIMIT,
        streamIds,
        httpCache: httpStreamCacheRef.current,
        tcpCache: tcpStreamCacheRef.current,
        udpCache: udpStreamCacheRef.current,
        httpInFlight: httpPrefetchInFlightRef.current,
        tcpInFlight: tcpPrefetchInFlightRef.current,
        udpInFlight: udpPrefetchInFlightRef.current,
        beginTask: captureTaskScopeRef.current.beginTask,
        fetchHttpStream: (id, signal) => bridge.getHttpStream(id, signal),
        fetchRawTcpStream: (id, signal) => bridge.getRawStreamPage("TCP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
        fetchRawUdpStream: (id, signal) => bridge.getRawStreamPage("UDP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
      });
    },
    [backendConnected, streamIds.http, streamIds.tcp, streamIds.udp],
  );

  const setActiveStream = useCallback(
    async (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => {
      await setActiveStreamState({
        backendConnected,
        activeCapturePath: activeCapturePathRef.current,
        protocol,
        streamId,
        streamSwitchSequences: streamSwitchSequencesRef.current,
        captureTaskScope: captureTaskScopeRef.current,
        httpCache: httpStreamCacheRef.current,
        tcpCache: tcpStreamCacheRef.current,
        udpCache: udpStreamCacheRef.current,
        applyHttpStream: (next) =>
          startTransition(() => {
            setHttpStream(next);
          }),
        applyTcpStream: (next) =>
          startTransition(() => {
            setTcpStream(next);
          }),
        applyUdpStream: (next) =>
          startTransition(() => {
            setUdpStream(next);
          }),
        fetchHttpStream: (id, signal) => bridge.getHttpStream(id, signal),
        fetchRawTcpStream: (id, signal) => bridge.getRawStreamPage("TCP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
        fetchRawUdpStream: (id, signal) => bridge.getRawStreamPage("UDP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
        recordMetric: recordStreamSwitchMetric,
        prefetchAdjacentStreams,
        setBackendStatus,
      });
    },
    [backendConnected, prefetchAdjacentStreams, recordStreamSwitchMetric, setBackendStatus],
  );

  const preparePacketStream = useCallback(
    async (
      packetId: number,
      preferredProtocol?: "HTTP" | "TCP" | "UDP",
      filterOverride?: string,
    ): Promise<PreparedPacketStream> => {
      return preparePacketStreamState({
        packetId,
        preferredProtocol,
        filterOverride,
        locatePacketById,
        setActiveStream,
      });
    },
    [locatePacketById, setActiveStream],
  );

  const persistStreamPayloads = useCallback(
    async (protocol: "HTTP" | "TCP" | "UDP", streamId: number, patches: Array<{ index: number; body: string }>) => {
      await persistStreamPayloadsState({
        protocol,
        streamId,
        patches,
        backendConnected,
        updateStreamPayloads: bridge.updateStreamPayloads,
        startTransition,
        setHttpStream,
        setTcpStream,
        setUdpStream,
        httpCache: httpStreamCacheRef.current,
        tcpCache: tcpStreamCacheRef.current,
        udpCache: udpStreamCacheRef.current,
      });
    },
    [backendConnected],
  );

  useSyncedRefValue(scheduleLoadMoreRef, scheduleLoadMore);
  useSyncedRefValue(refreshAnalysisResultRef, refreshAnalysisResult);
  useSyncedRefValue(updateProgressFromStatusRef, updateProgressFromStatus);

  useEffect(
    () => () => {
      captureTaskScopeRef.current.invalidate();
    },
    [],
  );

  useSelectedPacketResources({
    selectedPacketId,
    selectedPacket,
    selectedPacketDetail,
    captureTaskScopeRef,
    loadPacket: (packetId, signal) => bridge.getPacket(packetId, signal),
    loadRawHex: (packetId, signal) => bridge.getPacketRawHex(packetId, signal),
    loadLayers: (packetId, signal) => bridge.getPacketLayers(packetId, signal),
    setSelectedPacketDetail,
    setSelectedPacketRawHex,
    setSelectedPacketLayers,
  });

  const startCapture = useCallback(
    async (filePath?: string, filterOverride?: string) => {
      if (!backendConnected) {
        setBackendStatus(getCaptureOpenDisconnectedStatus());
        return false;
      }

      const captureSeq = ++captureSeqRef.current;
      filterSeqRef.current += 1;
      const effectiveFilter = filterOverride ?? displayFilter;
      const hadActiveCapture = Boolean(activeCapturePathRef.current);
      let pendingCapture = buildOpenedCaptureFromPath(filePath ?? "");

      try {
        const opened = await resolveOpenedCapture({
          filePath,
          openPcapFile: bridge.openPcapFile,
        });
        pendingCapture = opened;

        const started = await prepareAndStartOpenedCapture({
          opened,
          openedAt: new Date().toISOString(),
          hadActiveCapture,
          preloadProcessedRef,
          preloadTotalRef,
          parseFinishedRef,
          parseErrorRef,
          preloadingRef,
          setIsFilterLoading,
          setPacketPageError,
          setPreloadProcessed,
          setPreloadTotal,
          setIsPreloadingCapture,
          setCaptureTransaction,
          setBackendStatus,
          rememberRecentCapture,
          captureSeq,
          captureSeqRef,
          captureTaskScopeRef,
          prepareForCaptureReplacement,
          startStreamingPackets: bridge.startStreamingPackets,
        });
        if (!started) return false;

        const validatedFirstPage = await resolveCapturePreloadFirstPage({
          opened,
          filter: effectiveFilter,
          captureSeq,
          captureSeqRef,
          captureTaskScopeRef,
          parseFinishedRef,
          parseErrorRef,
          preloadProcessedRef,
          preloadTotalRef,
          listPacketsPage: bridge.listPacketsPage,
          getCaptureStatus: bridge.getCaptureStatus,
          waitForCaptureSignal,
          setTotalPackets,
          setPreloadProcessed,
        });
        if (!validatedFirstPage) return false;
        const finalized = await finalizeOpenedCapture({
          opened,
          validatedFirstPage,
          captureSeq,
          captureSeqRef,
          pageStartRef,
          hasMorePacketsRef,
          activeCapturePathRef,
          httpCache: httpStreamCacheRef.current,
          tcpCache: tcpStreamCacheRef.current,
          udpCache: udpStreamCacheRef.current,
          httpPrefetchInFlight: httpPrefetchInFlightRef.current,
          tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
          udpPrefetchInFlight: udpPrefetchInFlightRef.current,
          switchSequences: streamSwitchSequencesRef.current,
          switchDurationsRef: streamSwitchDurationsRef,
          switchHitsRef: streamSwitchHitsRef,
          setPackets,
          setTotalPackets,
          setPageStart,
          setHasPrevPackets,
          setHasMorePackets,
          setSelectedPacketId,
          setSelectedPacketDetail,
          setSelectedPacketRawHex,
          setSelectedPacketLayers,
          setStreamSwitchMetrics,
          resetAnalysisState,
          setFileMeta,
          setCaptureRevision,
          commitPacketPage,
          refreshStreamIndex,
          setCaptureTransaction,
          setBackendStatus,
          refreshAnalysisResult,
        });
        return finalized;
      } catch (error) {
        if (isAbortLikeError(error)) {
          return false;
        }
        if (captureSeq === captureSeqRef.current) {
          const failedTransaction = buildFailedCaptureTransactionStatus({
            error,
            parseError: parseErrorRef.current,
            hadActiveCapture,
            fallbackName: filePath?.trim() || "",
            fallbackPath: filePath?.trim() || "",
            pendingCaptureName: pendingCapture?.fileName,
            pendingCapturePath: pendingCapture?.filePath,
          });
          setCaptureTransaction(failedTransaction);
          setBackendStatus(failedTransaction.message);
        }
        return false;
      } finally {
        if (captureSeq === captureSeqRef.current) {
          stopCapturePreloading({
            preloadingRef,
            setIsPreloadingCapture,
          });
          wakeCaptureWaiters();
        }
      }
    },
    [
      backendConnected,
      commitPacketPage,
      displayFilter,
      prepareForCaptureReplacement,
      resetAnalysisState,
      refreshAnalysisResult,
      refreshStreamIndex,
      rememberRecentCapture,
      waitForCaptureSignal,
      wakeCaptureWaiters,
    ],
  );

  const applyFilter = useCallback(
    (value?: string) => {
      const nextFilter = value ?? displayFilter;

      void runPacketFilterAction({
        filter: nextFilter,
        syncDisplayFilter: value !== undefined,
        pollUntilSettled: true,
        shouldRun: Boolean(activeCapturePathRef.current && backendConnected && !isPreloadingCapture),
        filterSeqRef,
        loadPacketPage,
        resetPacketViewport,
        setDisplayFilter,
        setIsFilterLoading,
        setPacketPageError,
        setBackendStatus,
      });
    },
    [backendConnected, displayFilter, isPreloadingCapture, loadPacketPage, resetPacketViewport],
  );

  const clearFilter = useCallback(() => {
    void runPacketFilterAction({
      filter: "",
      syncDisplayFilter: true,
      pollUntilSettled: false,
      shouldRun: Boolean(activeCapturePathRef.current && backendConnected && !isPreloadingCapture),
      filterSeqRef,
      loadPacketPage,
      resetPacketViewport,
      setDisplayFilter,
      setIsFilterLoading,
      setPacketPageError,
      setBackendStatus,
    });
  }, [backendConnected, isPreloadingCapture, loadPacketPage, resetPacketViewport]);

  const selectPacket = useSelectedPacketAction({ setSelectedPacketDetail, setSelectedPacketId });

  const openCapture = useCallback(
    async (filePath?: string) => {
      setDisplayFilter("");
      return startCapture(filePath, "");
    },
    [startCapture],
  );

  const stopCapture = useCallback(async () => {
    await stopCaptureWorkflow({
      backendConnected,
      captureSeqRef,
      filterSeqRef,
      threatAnalysisSeqRef,
      parseFinishedRef,
      parseErrorRef,
      preloadingRef,
      setIsPreloadingCapture,
      setIsFilterLoading,
      cancelAllFrontendCaptureTasks,
      wakeCaptureWaiters,
      clearCaptureUiState,
      setBackendStatus,
      cancelMediaBatchTranscription: bridge.cancelMediaBatchTranscription,
      closeCapture: bridge.closeCapture,
    });
  }, [backendConnected, cancelAllFrontendCaptureTasks, clearCaptureUiState, setBackendStatus, wakeCaptureWaiters]);

  const value = useMemo<SentinelContextValue>(
    () => ({
      packets,
      totalPackets,
      currentPage,
      totalPages,
      isPreloadingCapture,
      preloadProcessed,
      preloadTotal,
      filteredPackets,
      hasMorePackets,
      hasPrevPackets,
      isPageLoading,
      isFilterLoading,
      packetPageError,
      captureTransaction,
      loadMorePackets,
      loadPrevPackets,
      jumpToPage,
      retryPacketPage,
      locatePacketById,
      selectedPacket,
      selectedPacketRawHex,
      selectedPacketId,
      displayFilter,
      setDisplayFilter,
      applyFilter,
      clearFilter,
      selectPacket,
      protocolTree,
      hexDump,
      threatHits,
      isThreatAnalysisLoading,
      threatAnalysisProgress,
      extractedObjects,
      httpStream,
      tcpStream,
      udpStream,
      streamIds,
      setActiveStream,
      persistStreamPayloads,
      streamSwitchMetrics,
      decryptionConfig,
      updateDecryptionConfig,
      fileMeta,
      captureRevision,
      recentCaptures,
      openCapture,
      stopCapture,
      preparePacketStream,
      backendConnected,
      backendStatus,
      mediaAnalysisProgress,
      tsharkStatus,
      isTSharkChecking,
      toolRuntimeCheckDegraded,
      setTSharkPath,
      toolRuntimeSnapshot,
      isToolRuntimeLoading,
      refreshToolRuntimeSnapshot,
      saveToolRuntimeConfig,
    }),
    [
      packets,
      totalPackets,
      currentPage,
      totalPages,
      filteredPackets,
      isPreloadingCapture,
      preloadProcessed,
      preloadTotal,
      hasMorePackets,
      hasPrevPackets,
      isPageLoading,
      isFilterLoading,
      packetPageError,
      captureTransaction,
      loadMorePackets,
      loadPrevPackets,
      jumpToPage,
      retryPacketPage,
      locatePacketById,
      selectedPacket,
      selectedPacketRawHex,
      selectedPacketId,
      displayFilter,
      applyFilter,
      clearFilter,
      selectPacket,
      protocolTree,
      hexDump,
      threatHits,
      isThreatAnalysisLoading,
      threatAnalysisProgress,
      extractedObjects,
      httpStream,
      tcpStream,
      udpStream,
      streamIds,
      setActiveStream,
      persistStreamPayloads,
      streamSwitchMetrics,
      decryptionConfig,
      updateDecryptionConfig,
      fileMeta,
      captureRevision,
      recentCaptures,
      openCapture,
      stopCapture,
      preparePacketStream,
      backendConnected,
      backendStatus,
      mediaAnalysisProgress,
      tsharkStatus,
      isTSharkChecking,
      toolRuntimeCheckDegraded,
      setTSharkPath,
      toolRuntimeSnapshot,
      isToolRuntimeLoading,
      refreshToolRuntimeSnapshot,
      saveToolRuntimeConfig,
    ],
  );

  return <SentinelContext.Provider value={value}>{children}</SentinelContext.Provider>;
}

export function useSentinel() {
  const ctx = useContext(SentinelContext);
  if (!ctx) {
    throw new Error("useSentinel must be used inside SentinelProvider");
  }
  return ctx;
}
