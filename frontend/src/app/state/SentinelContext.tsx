import {
  createContext,
  useContext,
  useMemo,
  useRef,
  type Dispatch,
  type PropsWithChildren,
  type SetStateAction,
} from "react";
import { backendClients } from "../integrations/backendClients";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { useBackendLifecycle } from "./hooks/useBackendLifecycle";
import { useSyncedRefValue } from "./hooks/useSyncedRefValue";
import { useAnalysisProgress } from "./hooks/useAnalysisProgress";
import { useCapturePreloadState } from "./hooks/useCapturePreloadState";
import { useCaptureSessionState } from "./hooks/useCaptureSessionState";
import { useDisplayFilterState } from "./hooks/useDisplayFilterState";
import type { SentinelContextValue } from "./sentinelTypes";
import { useCaptureSignalWaiters } from "./hooks/useCaptureSignalWaiters";
import { useRecentCapturesState } from "./hooks/useRecentCapturesState";
import { useProgressStatusUpdater } from "./hooks/useProgressStatusUpdater";
import { useRefreshAnalysisResult } from "./hooks/useRefreshAnalysisResult";
import { usePreparePacketStream } from "./hooks/usePreparePacketStream";
import { useFrontendCaptureTaskReset } from "./hooks/useFrontendCaptureTaskReset";
import { useClearCaptureUiState } from "./hooks/useClearCaptureUiState";
import { useDisplayFilterWorkflow } from "./hooks/useDisplayFilterWorkflow";
import { useCaptureReplacementPrepare } from "./hooks/useCaptureReplacementPrepare";
import { useCaptureStopWorkflow } from "./hooks/useCaptureStopWorkflow";
import { useCaptureTaskScopeCleanup } from "./hooks/useCaptureTaskScopeCleanup";
import { useOpenCaptureAction } from "./hooks/useOpenCaptureAction";
import { useStreamState } from "./hooks/useStreamState";
import { useCaptureStartWorkflow } from "./hooks/useCaptureStartWorkflow";
import { usePacketPageState } from "./hooks/usePacketPageState";

const SentinelContext = createContext<SentinelContextValue | null>(null);

export function SentinelProvider({ children }: PropsWithChildren) {
  const {
    isPreloadingCapture,
    preloadProcessed,
    preloadTotal,
    preloadProcessedRef,
    preloadTotalRef,
    setIsPreloadingCapture,
    setPreloadProcessed,
    setPreloadTotal,
  } = useCapturePreloadState();
  const { captureTransaction, setCaptureTransaction, fileMeta, setFileMeta, captureRevision, setCaptureRevision } =
    useCaptureSessionState();
  const { displayFilter, setDisplayFilter } = useDisplayFilterState();
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
  const { recentCaptures, rememberRecentCapture } = useRecentCapturesState();

  const captureTaskScopeRef = useRef(createCaptureTaskScope());
  const parseFinishedRef = useRef(false);
  const parseErrorRef = useRef("");
  const preloadingRef = useRef(false);
  const captureSeqRef = useRef(0);
  const filterSeqRef = useRef(0);
  const { captureWaitersRef, wakeCaptureWaiters, waitForCaptureSignal } = useCaptureSignalWaiters();
  const activeCapturePathRef = useRef("");
  const scheduleLoadMoreRef = useRef<() => void>(() => undefined);
  const setSelectedPacketIdRef = useRef<Dispatch<SetStateAction<number | null>>>(() => undefined);
  const refreshAnalysisResultRef = useRef<
    (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>
  >(async () => {});
  const updateProgressFromStatusRef = useRef<(message: string) => boolean>(() => false);
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
    setSelectedPacketId: (value) => setSelectedPacketIdRef.current(value),
    setMediaAnalysisProgress,
    setThreatAnalysisProgress,
    setIsThreatAnalysisLoading,
  });

  const {
    httpStream,
    setHttpStream,
    tcpStream,
    setTcpStream,
    udpStream,
    setUdpStream,
    streamIds,
    setStreamIds,
    httpStreamCacheRef,
    tcpStreamCacheRef,
    udpStreamCacheRef,
    httpPrefetchInFlightRef,
    tcpPrefetchInFlightRef,
    udpPrefetchInFlightRef,
    streamSwitchSequencesRef,
    streamSwitchMetrics,
    setStreamSwitchMetrics,
    streamSwitchDurationsRef,
    streamSwitchHitsRef,
    refreshStreamIndex,
    setActiveStream,
    persistStreamPayloads,
  } = useStreamState({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    fetchHttpStream: backendClients.stream.getHttpStream,
    fetchRawStreamPage: backendClients.stream.getRawStreamPage,
    listStreamIds: backendClients.stream.listStreamIds,
    setBackendStatus,
    updateStreamPayloads: backendClients.stream.updateStreamPayloads,
  });

  const {
    packets,
    setPackets,
    totalPackets,
    setTotalPackets,
    setPageStart,
    hasMorePackets,
    setHasMorePackets,
    hasPrevPackets,
    setHasPrevPackets,
    isPageLoading,
    setIsPageLoading,
    isFilterLoading,
    setIsFilterLoading,
    packetPageError,
    setPacketPageError,
    pageStartRef,
    packetPageSeqRef,
    hasMorePacketsRef,
    loadMoreScheduledRef,
    commitPacketPage,
    resetPacketViewport,
    loadPacketPage,
    loadMorePackets,
    loadPrevPackets,
    jumpToPage,
    retryPacketPage,
    locatePacketById,
    scheduleLoadMore,
    filteredPackets,
    selectedPacket,
    protocolTree,
    hexDump,
    currentPage,
    totalPages,
    selectedPacketId,
    selectedPacketRawHex,
    selectPacket,
    setSelectedPacketId,
    setSelectedPacketDetail,
    setSelectedPacketRawHex,
    setSelectedPacketLayers,
  } = usePacketPageState({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    displayFilter,
    listPacketsPage: backendClients.packet.listPacketsPage,
    locatePacketPage: backendClients.packet.locatePacketPage,
    loadPacket: backendClients.packet.getPacket,
    loadRawHex: backendClients.packet.getPacketRawHex,
    loadLayers: backendClients.packet.getPacketLayers,
    setBackendStatus,
    setDisplayFilter,
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
    stopStreamingPackets: backendClients.capture.stopStreamingPackets,
    prepareCaptureReplacement: backendClients.capture.prepareCaptureReplacement,
  });

  const refreshAnalysisResult = useRefreshAnalysisResult({
    activeCapturePathRef,
    backendConnected,
    captureTaskScopeRef,
    refreshAnalysisResultImpl,
    setBackendStatus,
  });

  const preparePacketStream = usePreparePacketStream({
    locatePacketById,
    setActiveStream,
  });

  useSyncedRefValue(scheduleLoadMoreRef, scheduleLoadMore);
  useSyncedRefValue(refreshAnalysisResultRef, refreshAnalysisResult);
  useSyncedRefValue(updateProgressFromStatusRef, updateProgressFromStatus);
  useSyncedRefValue(setSelectedPacketIdRef, setSelectedPacketId);
  useSyncedRefValue(hasMorePacketsRef, hasMorePackets);
  useCaptureTaskScopeCleanup(captureTaskScopeRef);

  const startCapture = useCaptureStartWorkflow({
    context: {
      backendConnected,
      displayFilter,
    },
    refs: {
      activeCapturePathRef,
      captureSeqRef,
      captureTaskScopeRef,
      filterSeqRef,
      hasMorePacketsRef,
      pageStartRef,
      parseErrorRef,
      parseFinishedRef,
      preloadingRef,
      preloadProcessedRef,
      preloadTotalRef,
    },
    streamRefs: {
      httpCacheRef: httpStreamCacheRef,
      tcpCacheRef: tcpStreamCacheRef,
      udpCacheRef: udpStreamCacheRef,
      httpPrefetchInFlightRef,
      tcpPrefetchInFlightRef,
      udpPrefetchInFlightRef,
      streamSwitchDurationsRef,
      streamSwitchHitsRef,
      streamSwitchSequencesRef,
    },
    setters: {
      setBackendStatus,
      setCaptureRevision,
      setCaptureTransaction,
      setFileMeta,
      setHasMorePackets,
      setHasPrevPackets,
      setIsFilterLoading,
      setIsPreloadingCapture,
      setPacketPageError,
      setPackets,
      setPageStart,
      setPreloadProcessed,
      setPreloadTotal,
      setSelectedPacketDetail,
      setSelectedPacketId,
      setSelectedPacketLayers,
      setSelectedPacketRawHex,
      setStreamSwitchMetrics,
      setTotalPackets,
    },
    clients: {
      getCaptureStatus: backendClients.capture.getCaptureStatus,
      listPacketsPage: backendClients.packet.listPacketsPage,
      openPcapFile: backendClients.capture.openPcapFile,
      startStreamingPackets: backendClients.capture.startStreamingPackets,
    },
    hooks: {
      commitPacketPage,
      prepareForCaptureReplacement,
      refreshAnalysisResult,
      refreshStreamIndex,
      rememberRecentCapture,
      resetAnalysisState,
      waitForCaptureSignal,
      wakeCaptureWaiters,
    },
  });

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
    cancelMediaBatchTranscription: backendClients.media.cancelMediaBatchTranscription,
    closeCapture: backendClients.capture.closeCapture,
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
