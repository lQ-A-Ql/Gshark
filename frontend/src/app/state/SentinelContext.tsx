import { createContext, useCallback, useContext, useMemo, useRef, useState, type PropsWithChildren } from "react";
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
import { finalizeOpenedCapture } from "./captureFinalizeWorkflow";
import { PAGE_SIZE, STREAM_PREFETCH_LIMIT } from "./captureConstants";
import { EMPTY_BINARY_STREAM, EMPTY_HTTP_STREAM, createEmptyStreamIds, createEmptyUdpStream } from "./streamState";
import { createStreamSwitchSequences } from "./streamSwitchSequence";
import { resolveCapturePreloadFirstPage } from "./capturePreloadProbe";
import type { SentinelContextValue } from "./sentinelTypes";
import { useStreamSwitchMetrics } from "./hooks/useStreamSwitchMetrics";
import { useCaptureSignalWaiters } from "./hooks/useCaptureSignalWaiters";
import { useRecentCapturesState } from "./hooks/useRecentCapturesState";
import { useSelectedPacketAction } from "./hooks/useSelectedPacketAction";
import { usePacketPageCancellation } from "./hooks/usePacketPageCancellation";
import { useProgressStatusUpdater } from "./hooks/useProgressStatusUpdater";
import { useScheduledPacketPageLoad } from "./hooks/useScheduledPacketPageLoad";
import { useStreamIndexRefresh } from "./hooks/useStreamIndexRefresh";
import { useStreamPayloadPersistence } from "./hooks/useStreamPayloadPersistence";
import { useRefreshAnalysisResult } from "./hooks/useRefreshAnalysisResult";
import { usePacketPageCommit } from "./hooks/usePacketPageCommit";
import { usePreparePacketStream } from "./hooks/usePreparePacketStream";
import { usePacketViewportReset } from "./hooks/usePacketViewportReset";
import { usePacketPageLoad } from "./hooks/usePacketPageLoad";
import { usePacketLocateById } from "./hooks/usePacketLocateById";
import { usePacketPageNavigation } from "./hooks/usePacketPageNavigation";
import { useStreamAdjacentPrefetch } from "./hooks/useStreamAdjacentPrefetch";
import { useActiveStreamSwitch } from "./hooks/useActiveStreamSwitch";
import { useFrontendCaptureTaskReset } from "./hooks/useFrontendCaptureTaskReset";
import { useClearCaptureUiState } from "./hooks/useClearCaptureUiState";
import { useDisplayFilterWorkflow } from "./hooks/useDisplayFilterWorkflow";
import { useCaptureReplacementPrepare } from "./hooks/useCaptureReplacementPrepare";
import { useCaptureStopWorkflow } from "./hooks/useCaptureStopWorkflow";
import { useSentinelDerivedView } from "./hooks/useSentinelDerivedView";
import { useCaptureTaskScopeCleanup } from "./hooks/useCaptureTaskScopeCleanup";
import { useOpenCaptureAction } from "./hooks/useOpenCaptureAction";

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

  const cancelAllFrontendCaptureTasks = useFrontendCaptureTaskReset({
    captureTaskScopeRef,
    packetPageSeqRef,
    threatAnalysisSeqRef,
    streamSwitchSequencesRef,
    httpPrefetchInFlightRef,
    tcpPrefetchInFlightRef,
    udpPrefetchInFlightRef,
    loadMoreScheduledRef,
    setIsPageLoading,
    setPacketPageError,
  });

  const cancelPacketPageLoad = usePacketPageCancellation({
    captureTaskScopeRef,
    packetPageSeqRef,
    setIsPageLoading,
  });

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

  const resetPacketViewport = usePacketViewportReset({
    cancelPacketPageLoad,
    hasMorePacketsRef,
    pageStartRef,
    setHasMorePackets,
    setHasPrevPackets,
    setPackets,
    setPageStart,
    setSelectedPacketDetail,
    setSelectedPacketId,
    setSelectedPacketLayers,
    setSelectedPacketRawHex,
    setTotalPackets,
  });

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

  const loadPacketPage = usePacketPageLoad({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    commitPacketPage,
    displayFilter,
    listPacketsPage: bridge.listPacketsPage,
    packetPageSeqRef,
    pageSize: PAGE_SIZE,
    setBackendStatus,
    setIsFilterLoading,
    setIsPageLoading,
    setPacketPageError,
  });

  const { jumpToPage, loadMorePackets, loadPrevPackets, retryPacketPage } = usePacketPageNavigation({
    displayFilter,
    loadPacketPage,
    pageSize: PAGE_SIZE,
    pageStartRef,
    setBackendStatus,
    totalPackets,
  });

  const locatePacketById = usePacketLocateById({
    activeCapturePathRef,
    captureTaskScopeRef,
    displayFilter,
    loadPacketPage,
    locatePacketPage: bridge.locatePacketPage,
    pageSize: PAGE_SIZE,
    setBackendStatus,
    setDisplayFilter,
    setSelectedPacketId,
  });

  const scheduleLoadMore = useScheduledPacketPageLoad({ loadMoreScheduledRef, pageStartRef, loadPacketPage });

  const updateProgressFromStatus = useProgressStatusUpdater({
    preloadProcessedRef,
    preloadTotalRef,
    setPreloadProcessed,
    setPreloadTotal,
    setTotalPackets,
    setMediaAnalysisProgress,
    setThreatAnalysisProgress,
  });

  const prepareForCaptureReplacement = useCaptureReplacementPrepare({
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

  const { filteredPackets, selectedPacket, protocolTree, hexDump, currentPage, totalPages } = useSentinelDerivedView({
    packets,
    selectedPacketId,
    selectedPacketDetail,
    selectedPacketLayers,
    pageStart,
    totalPackets,
    pageSize: PAGE_SIZE,
  });

  const refreshAnalysisResult = useRefreshAnalysisResult({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    refreshAnalysisResultImpl,
    setBackendStatus,
  });

  const refreshStreamIndex = useStreamIndexRefresh({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    listStreamIds: bridge.listStreamIds,
    setBackendStatus,
    setStreamIds,
  });

  const prefetchAdjacentStreams = useStreamAdjacentPrefetch({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream: bridge.getHttpStream,
    fetchRawStreamPage: bridge.getRawStreamPage,
    httpCacheRef: httpStreamCacheRef,
    httpPrefetchInFlightRef,
    prefetchLimit: STREAM_PREFETCH_LIMIT,
    streamIds,
    tcpCacheRef: tcpStreamCacheRef,
    tcpPrefetchInFlightRef,
    udpCacheRef: udpStreamCacheRef,
    udpPrefetchInFlightRef,
  });

  const setActiveStream = useActiveStreamSwitch({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream: bridge.getHttpStream,
    fetchRawStreamPage: bridge.getRawStreamPage,
    httpCacheRef: httpStreamCacheRef,
    prefetchAdjacentStreams,
    recordStreamSwitchMetric,
    setBackendStatus,
    setHttpStream,
    setTcpStream,
    setUdpStream,
    streamSwitchSequencesRef,
    tcpCacheRef: tcpStreamCacheRef,
    udpCacheRef: udpStreamCacheRef,
  });

  const preparePacketStream = usePreparePacketStream({
    locatePacketById,
    setActiveStream,
  });

  const persistStreamPayloads = useStreamPayloadPersistence({
    backendConnected,
    httpCacheRef: httpStreamCacheRef,
    setHttpStream,
    setTcpStream,
    setUdpStream,
    tcpCacheRef: tcpStreamCacheRef,
    udpCacheRef: udpStreamCacheRef,
    updateStreamPayloads: bridge.updateStreamPayloads,
  });

  useSyncedRefValue(scheduleLoadMoreRef, scheduleLoadMore);
  useSyncedRefValue(refreshAnalysisResultRef, refreshAnalysisResult);
  useSyncedRefValue(updateProgressFromStatusRef, updateProgressFromStatus);
  useSyncedRefValue(hasMorePacketsRef, hasMorePackets);
  useCaptureTaskScopeCleanup(captureTaskScopeRef);

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

  const { applyFilter, clearFilter } = useDisplayFilterWorkflow({
    activeCapturePathRef,
    backendConnected,
    displayFilter,
    isPreloadingCapture,
    filterSeqRef,
    loadPacketPage,
    resetPacketViewport,
    setDisplayFilter,
    setIsFilterLoading,
    setPacketPageError,
    setBackendStatus,
  });

  const selectPacket = useSelectedPacketAction({ setSelectedPacketDetail, setSelectedPacketId });

  const openCapture = useOpenCaptureAction({ setDisplayFilter, startCapture });

  const stopCapture = useCaptureStopWorkflow({
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
