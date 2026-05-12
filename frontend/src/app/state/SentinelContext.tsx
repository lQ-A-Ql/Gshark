import { createContext, useContext, useMemo, useRef, useState, type PropsWithChildren } from "react";
import type { Packet } from "../core/types";
import { backendClients } from "../integrations/backendClients";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { useBackendLifecycle } from "./hooks/useBackendLifecycle";
import { useSyncedRefValue } from "./hooks/useSyncedRefValue";
import { useAnalysisProgress } from "./hooks/useAnalysisProgress";
import { createInitialCaptureFileMeta } from "./captureOpenState";
import { createIdleCaptureTransactionStatus } from "./captureTransactionStatus";
import { PAGE_SIZE } from "./captureConstants";
import type { SentinelContextValue } from "./sentinelTypes";
import { useCaptureSignalWaiters } from "./hooks/useCaptureSignalWaiters";
import { useRecentCapturesState } from "./hooks/useRecentCapturesState";
import { usePacketPageCancellation } from "./hooks/usePacketPageCancellation";
import { useProgressStatusUpdater } from "./hooks/useProgressStatusUpdater";
import { useScheduledPacketPageLoad } from "./hooks/useScheduledPacketPageLoad";
import { useRefreshAnalysisResult } from "./hooks/useRefreshAnalysisResult";
import { usePacketPageCommit } from "./hooks/usePacketPageCommit";
import { usePreparePacketStream } from "./hooks/usePreparePacketStream";
import { usePacketViewportReset } from "./hooks/usePacketViewportReset";
import { usePacketPageLoad } from "./hooks/usePacketPageLoad";
import { usePacketLocateById } from "./hooks/usePacketLocateById";
import { usePacketPageNavigation } from "./hooks/usePacketPageNavigation";
import { useFrontendCaptureTaskReset } from "./hooks/useFrontendCaptureTaskReset";
import { useClearCaptureUiState } from "./hooks/useClearCaptureUiState";
import { useDisplayFilterWorkflow } from "./hooks/useDisplayFilterWorkflow";
import { useCaptureReplacementPrepare } from "./hooks/useCaptureReplacementPrepare";
import { useCaptureStopWorkflow } from "./hooks/useCaptureStopWorkflow";
import { useCaptureTaskScopeCleanup } from "./hooks/useCaptureTaskScopeCleanup";
import { useOpenCaptureAction } from "./hooks/useOpenCaptureAction";
import { useSelectedPacketState } from "./hooks/useSelectedPacketState";
import { useStreamState } from "./hooks/useStreamState";
import { useCaptureStartWorkflow } from "./hooks/useCaptureStartWorkflow";

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
  const scheduleLoadMoreRef = useRef<() => void>(() => undefined);
  const refreshAnalysisResultRef = useRef<
    (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>
  >(async () => {});
  const updateProgressFromStatusRef = useRef<(message: string) => boolean>(() => false);
  const {
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
  } = useSelectedPacketState({
    packets,
    pageStart,
    totalPackets,
    pageSize: PAGE_SIZE,
    captureTaskScopeRef,
    loadPacket: backendClients.packet.getPacket,
    loadRawHex: backendClients.packet.getPacketRawHex,
    loadLayers: backendClients.packet.getPacketLayers,
  });
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
    listPacketsPage: backendClients.packet.listPacketsPage,
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
    locatePacketPage: backendClients.packet.locatePacketPage,
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
  useSyncedRefValue(hasMorePacketsRef, hasMorePackets);
  useCaptureTaskScopeCleanup(captureTaskScopeRef);

  const startCapture = useCaptureStartWorkflow({
    backendConnected,
    displayFilter,
    activeCapturePathRef,
    captureSeqRef,
    captureTaskScopeRef,
    filterSeqRef,
    hasMorePacketsRef,
    httpCacheRef: httpStreamCacheRef,
    httpPrefetchInFlightRef,
    pageStartRef,
    parseErrorRef,
    parseFinishedRef,
    preloadingRef,
    preloadProcessedRef,
    preloadTotalRef,
    streamSwitchDurationsRef,
    streamSwitchHitsRef,
    streamSwitchSequencesRef,
    tcpCacheRef: tcpStreamCacheRef,
    tcpPrefetchInFlightRef,
    udpCacheRef: udpStreamCacheRef,
    udpPrefetchInFlightRef,
    commitPacketPage,
    getCaptureStatus: backendClients.capture.getCaptureStatus,
    listPacketsPage: backendClients.packet.listPacketsPage,
    openPcapFile: backendClients.capture.openPcapFile,
    prepareForCaptureReplacement,
    refreshAnalysisResult,
    refreshStreamIndex,
    rememberRecentCapture,
    resetAnalysisState,
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
    startStreamingPackets: backendClients.capture.startStreamingPackets,
    waitForCaptureSignal,
    wakeCaptureWaiters,
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
