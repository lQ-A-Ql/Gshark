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
import { buildHexDump, buildProtocolTree, buildProtocolTreeFromLayers } from "../core/engine";
import type { BinaryStream, HttpStream, Packet, RecentCapture, StreamSwitchMetrics } from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { isAbortLikeError } from "../utils/asyncControl";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { useBackendLifecycle } from "./hooks/useBackendLifecycle";
import { useSelectedPacketArtifact } from "./hooks/useSelectedPacketArtifact";
import { useSelectedPacketDetail } from "./hooks/useSelectedPacketDetail";
import { useSyncedRefValue } from "./hooks/useSyncedRefValue";
import {
  phaseLabelForMediaProgress,
  phaseLabelForThreatProgress,
  useAnalysisProgress,
} from "./hooks/useAnalysisProgress";
import {
  classifyMediaProgressPhase,
  classifyThreatProgressPhase,
  computeMediaProgressPercent,
  computeThreatProgressPercent,
} from "./progressHelpers";
import { parseProgressStatus, pushRecentLabel } from "./progressStatus";
import { readRecentCaptures, updateRecentCaptures, writeRecentCaptures } from "./recentCaptures";
import {
  getCurrentPacketPage,
  getNextPacketCursor,
  getPacketPageCursor,
  getPrevPacketCursor,
  getTotalPacketPages,
  packetPageHasPacket,
} from "./packetPagination";
import {
  keepSelectedPacketDetailForId,
  resolveSelectedPacket,
  shouldLoadSelectedPacketArtifacts,
  shouldLoadSelectedPacketDetail,
} from "./selectedPacketState";
import { getPacketPageRetryStatus } from "./packetPageStatus";
import {
  getCaptureCloseErrorMessage,
  getCaptureStopDoneStatus,
  getCaptureStopRequestStatus,
} from "./captureStopStatus";
import {
  CAPTURE_PRELOAD_TIMEOUT_MS,
  getCaptureEmptyParseError,
  getCaptureOpenDisconnectedStatus,
  getCaptureOpenErrorMessage,
  getCapturePreloadDoneStatus,
  getCapturePreloadTimeoutError,
  getCapturePreloadWorkingStatus,
} from "./capturePreloadStatus";
import {
  buildCaptureFileMeta,
  buildOpenedCaptureFromPath,
  buildRecentCapture,
  createClosedCaptureFileMeta,
  createInitialCaptureFileMeta,
} from "./captureOpenState";
import {
  createFailedCaptureTransactionStatus,
  createIdleCaptureTransactionStatus,
  createPendingCaptureTransactionStatus,
} from "./captureTransactionStatus";
import { finishCaptureParseRuntime, startCaptureParseRuntime, stopCapturePreloading } from "./captureParseRuntimeState";
import { resetPacketViewportState, resetPreloadCounterState } from "./captureResetState";
import { cancelFrontendCaptureTasks } from "./captureTaskReset";
import { loadPacketPageState } from "./packetPageLoad";
import { runPacketFilterWorkflow } from "./packetFilterWorkflow";
import { locatePacketByIdWorkflow } from "./packetLocateWorkflow";
import {
  PAGE_SIZE,
  PRELOAD_POLL_INTERVAL_MS,
  PRELOAD_SIGNAL_WAIT_MS,
  RAW_STREAM_PAGE_SIZE,
  STREAM_PREFETCH_LIMIT,
} from "./captureConstants";
import {
  EMPTY_BINARY_STREAM,
  EMPTY_HTTP_STREAM,
  EMPTY_SWITCH_METRICS,
  createEmptyStreamIds,
  createEmptyUdpStream,
  getStreamIdsForProtocol,
  prettySize,
} from "./streamState";
import { pickAdjacentStreamTargets } from "./streamPrefetchPlan";
import { resolveStreamPrefetchTask } from "./streamPrefetchTask";
import { resolvePacketStreamProtocol } from "./streamProtocol";
import { applyCachedStreamSwitch } from "./streamSwitchCache";
import { commitLoadedStreamSwitch } from "./streamSwitchCommit";
import { resolveStreamSwitchTask } from "./streamSwitchTask";
import { refreshStreamIndexState } from "./streamIndexRefresh";
import { scheduleStreamPrefetch } from "./streamPrefetchScheduler";
import { persistStreamPayloadsState } from "./streamPayloadPersist";
import {
  bumpStreamSwitchSequence,
  createStreamSwitchSequences,
  isLatestStreamSwitchSequence,
} from "./streamSwitchSequence";
import {
  createEmptyStreamSwitchDurations,
  createEmptyStreamSwitchHits,
  resetStreamRuntimeRefs,
} from "./streamRuntimeReset";
import { recordStreamSwitchMetricSample } from "./streamSwitchMetrics";
import {
  waitForCaptureSignal as waitForCaptureSignalUtil,
  wakeCaptureWaiters as wakeCaptureWaitersUtil,
} from "./captureSignal";
import { isCommittedCaptureStatusForPath } from "./captureCommitStatus";
import type { PreparedPacketStream, SentinelContextValue } from "./sentinelTypes";

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
  const [recentCaptures, setRecentCaptures] = useState<RecentCapture[]>(() => readRecentCaptures());

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
  const captureWaitersRef = useRef(new Set<() => void>());
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
  const [streamSwitchMetrics, setStreamSwitchMetrics] = useState<StreamSwitchMetrics>(EMPTY_SWITCH_METRICS);
  const streamSwitchDurationsRef = useRef(createEmptyStreamSwitchDurations());
  const streamSwitchHitsRef = useRef(createEmptyStreamSwitchHits());
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

  const recordStreamSwitchMetric = useCallback(
    (protocol: "HTTP" | "TCP" | "UDP", elapsedMs: number, cacheHit: boolean) => {
      setStreamSwitchMetrics(
        recordStreamSwitchMetricSample({
          protocol,
          elapsedMs,
          cacheHit,
          switchDurationsRef: streamSwitchDurationsRef,
          switchHitsRef: streamSwitchHitsRef,
        }),
      );
    },
    [],
  );

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

  const cancelPacketPageLoad = useCallback(() => {
    packetPageSeqRef.current += 1;
    captureTaskScopeRef.current.abortTask("packet-page");
    setIsPageLoading(false);
  }, []);

  const commitPacketPage = useCallback(
    (safeCursor: number, page: { items: Packet[]; total: number; hasMore: boolean }) => {
      pageStartRef.current = safeCursor;
      setPageStart(safeCursor);
      setTotalPackets(page.total);
      setPackets(page.items);
      setSelectedPacketId((prev) => {
        if (prev == null) return null;
        return packetPageHasPacket(page.items, prev) ? prev : null;
      });
      setSelectedPacketDetail((prev) => {
        if (!prev) return null;
        return packetPageHasPacket(page.items, prev.id) ? prev : null;
      });
      setSelectedPacketRawHex("");
      setSelectedPacketLayers(null);
      setHasPrevPackets(safeCursor > 0);
      setPacketPageError("");
      hasMorePacketsRef.current = page.hasMore;
      setHasMorePackets(page.hasMore);
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
    resetPreloadCounterState({
      preloadProcessedRef,
      preloadTotalRef,
      setPreloadProcessed,
      setPreloadTotal,
    });
    resetAnalysisState();
    setHttpStream(EMPTY_HTTP_STREAM);
    setTcpStream(EMPTY_BINARY_STREAM);
    setUdpStream(createEmptyUdpStream());
    setStreamIds(createEmptyStreamIds());
    resetStreamRuntimeRefs({
      httpCache: httpStreamCacheRef.current,
      tcpCache: tcpStreamCacheRef.current,
      udpCache: udpStreamCacheRef.current,
      httpPrefetchInFlight: httpPrefetchInFlightRef.current,
      tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
      udpPrefetchInFlight: udpPrefetchInFlightRef.current,
      switchDurationsRef: streamSwitchDurationsRef,
      switchHitsRef: streamSwitchHitsRef,
    });
    setStreamSwitchMetrics(EMPTY_SWITCH_METRICS);
    setFileMeta(createClosedCaptureFileMeta());
    setPacketPageError("");
    setCaptureTransaction(createIdleCaptureTransactionStatus(false));
    activeCapturePathRef.current = "";
    setCaptureRevision((prev) => prev + 1);
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
    const next = getNextPacketCursor(pageStartRef.current, PAGE_SIZE);
    await loadPacketPage(next);
  }, [loadPacketPage]);

  const loadPrevPackets = useCallback(async () => {
    const prev = getPrevPacketCursor(pageStartRef.current, PAGE_SIZE);
    await loadPacketPage(prev);
  }, [loadPacketPage]);

  const jumpToPage = useCallback(
    async (page: number) => {
      const cursor = getPacketPageCursor(page, totalPackets, PAGE_SIZE);
      await loadPacketPage(cursor);
    },
    [loadPacketPage, totalPackets],
  );

  const retryPacketPage = useCallback(async () => {
    setBackendStatus(getPacketPageRetryStatus(displayFilter));
    await loadPacketPage(pageStartRef.current);
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
    const progress = parseProgressStatus(message);
    if (!progress.consumed) {
      return false;
    }
    if (progress.kind === "malformed") {
      return true;
    }
    if (progress.kind === "media") {
      const { current, total, label } = progress;
      const progressPhase = classifyMediaProgressPhase(label);
      const percent = computeMediaProgressPercent(progressPhase, current, total);
      setMediaAnalysisProgress((prev) => {
        const nextRecent = label !== prev.label ? pushRecentLabel(prev.recent, label, 4) : prev.recent;
        return {
          active: progressPhase !== "complete" && (total <= 0 || current < total),
          current,
          total,
          label,
          phase: progressPhase,
          phaseLabel: phaseLabelForMediaProgress(progressPhase),
          percent,
          recent: nextRecent,
        };
      });
      return true;
    }
    if (progress.kind === "threat") {
      const { current, total, label } = progress;
      const progressPhase = classifyThreatProgressPhase(label);
      const percent = computeThreatProgressPercent(progressPhase, current, total);
      setThreatAnalysisProgress((prev) => {
        const nextRecent = label !== prev.label ? pushRecentLabel(prev.recent, label, 5) : prev.recent;
        return {
          active: progressPhase !== "complete" && (total <= 0 || current < total),
          current,
          total,
          label,
          phase: progressPhase,
          phaseLabel: phaseLabelForThreatProgress(progressPhase),
          percent,
          recent: nextRecent,
        };
      });
      return true;
    }
    const { phase, processed, total } = progress;
    if (total > 0) {
      setPreloadTotal(total);
      preloadTotalRef.current = total;
      setTotalPackets(total);
    }
    if (phase === "counting") {
      setPreloadProcessed(0);
      preloadProcessedRef.current = 0;
      return true;
    }
    const normalized = Math.max(0, processed);
    setPreloadProcessed(normalized);
    preloadProcessedRef.current = normalized;
    return true;
  }, []);

  const wakeCaptureWaiters = useCallback(() => {
    wakeCaptureWaitersUtil(captureWaitersRef.current);
  }, []);

  const prepareForCaptureReplacement = useCallback(async () => {
    cancelAllFrontendCaptureTasks();
    wakeCaptureWaiters();
    finishCaptureParseRuntime({
      parseFinishedRef,
      parseErrorRef,
      preloadingRef,
      setIsPreloadingCapture,
    });
    setIsFilterLoading(false);
    setPreloadProcessed(0);
    setPreloadTotal(0);
    preloadProcessedRef.current = 0;
    preloadTotalRef.current = 0;

    if (!backendConnected) return;
    await bridge.stopStreamingPackets().catch(() => null);
    await bridge.prepareCaptureReplacement().catch(() => null);
  }, [backendConnected, cancelAllFrontendCaptureTasks, wakeCaptureWaiters]);

  const waitForCaptureSignal = useCallback(
    (delayMs: number) => waitForCaptureSignalUtil(captureWaitersRef.current, delayMs),
    [],
  );

  useEffect(() => {
    hasMorePacketsRef.current = hasMorePackets;
  }, [hasMorePackets]);

  const rememberRecentCapture = useCallback((entry: RecentCapture) => {
    setRecentCaptures((prev) => {
      const next = updateRecentCaptures(prev, entry);
      writeRecentCaptures(next);
      return next;
    });
  }, []);

  const filteredPackets = useMemo(() => packets, [packets]);

  const selectedPacket = useMemo(
    () => resolveSelectedPacket(filteredPackets, selectedPacketId, selectedPacketDetail),
    [filteredPackets, selectedPacketDetail, selectedPacketId],
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
      if (!backendConnected || !activeCapturePathRef.current || currentStreamId < 0 || STREAM_PREFETCH_LIMIT <= 0)
        return;

      const ids = getStreamIdsForProtocol(streamIds, protocol);
      const targets = pickAdjacentStreamTargets(ids, currentStreamId, STREAM_PREFETCH_LIMIT);
      for (const targetId of targets) {
        const { taskKey, cache, inFlight, fetchStream } = resolveStreamPrefetchTask({
          protocol,
          targetId,
          httpCache: httpStreamCacheRef.current,
          tcpCache: tcpStreamCacheRef.current,
          udpCache: udpStreamCacheRef.current,
          httpInFlight: httpPrefetchInFlightRef.current,
          tcpInFlight: tcpPrefetchInFlightRef.current,
          udpInFlight: udpPrefetchInFlightRef.current,
          fetchHttpStream: (id, signal) => bridge.getHttpStream(id, signal),
          fetchRawTcpStream: (id, signal) => bridge.getRawStreamPage("TCP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
          fetchRawUdpStream: (id, signal) => bridge.getRawStreamPage("UDP", id, 0, RAW_STREAM_PAGE_SIZE, signal),
        });
        scheduleStreamPrefetch({
          targetId,
          taskKey,
          cache,
          inFlight,
          beginTask: captureTaskScopeRef.current.beginTask,
          fetchStream,
        });
      }
    },
    [backendConnected, streamIds.http, streamIds.tcp, streamIds.udp],
  );

  const setActiveStream = useCallback(
    async (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => {
      if (!backendConnected || !activeCapturePathRef.current || streamId < 0) return;
      const startedAt = typeof performance !== "undefined" ? performance.now() : Date.now();
      let cacheHit = false;
      const task = captureTaskScopeRef.current.beginTask(`${protocol.toLowerCase()}-stream`);

      const requestSeq = bumpStreamSwitchSequence(streamSwitchSequencesRef.current, protocol);

      const isLatest = () =>
        isLatestStreamSwitchSequence(streamSwitchSequencesRef.current, protocol, requestSeq, task.isCurrent);

      const commitCachedSwitch = <T extends HttpStream | BinaryStream>(
        metricProtocol: "HTTP" | "TCP" | "UDP",
        cache: Map<number, T>,
        apply: (stream: T) => void,
      ) => {
        if (!applyCachedStreamSwitch({ cache, streamId, isLatest, apply })) {
          return false;
        }
        cacheHit = true;
        const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;
        recordStreamSwitchMetric(metricProtocol, elapsed, cacheHit);
        prefetchAdjacentStreams(metricProtocol, streamId);
        return true;
      };

      const commitLoadedSwitch = <T extends HttpStream | BinaryStream>(
        metricProtocol: "HTTP" | "TCP" | "UDP",
        cache: Map<number, T>,
        stream: T,
        apply: (stream: T) => void,
      ) => {
        commitLoadedStreamSwitch({
          protocol: metricProtocol,
          requestedStreamId: streamId,
          stream,
          cache,
          apply,
          startedAt,
          recordMetric: recordStreamSwitchMetric,
          prefetchAdjacentStreams,
        });
      };

      const switchTask = resolveStreamSwitchTask({
        protocol,
        streamId,
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
      });

      try {
        if (commitCachedSwitch(switchTask.protocol, switchTask.cache, switchTask.applyStream)) {
          return;
        }
        switchTask.applyStream(switchTask.loadingStream);
        const stream = await switchTask.fetchStream(streamId, task.signal);
        if (!isLatest()) return;
        commitLoadedSwitch(switchTask.protocol, switchTask.cache, stream, switchTask.applyStream);
      } catch (error) {
        if (!isLatest()) return;
        if (isAbortLikeError(error, task.signal)) {
          return;
        }
        setBackendStatus(error instanceof Error && error.message ? error.message : "流切换失败");
      } finally {
        task.finish();
      }
    },
    [backendConnected, prefetchAdjacentStreams, recordStreamSwitchMetric],
  );

  const preparePacketStream = useCallback(
    async (
      packetId: number,
      preferredProtocol?: "HTTP" | "TCP" | "UDP",
      filterOverride?: string,
    ): Promise<PreparedPacketStream> => {
      const packet = await locatePacketById(packetId, filterOverride);
      if (!packet || packet.streamId == null || packet.streamId < 0) {
        return { packet, protocol: null, streamId: null };
      }

      const protocol = resolvePacketStreamProtocol(packet.proto, preferredProtocol ?? null);

      await setActiveStream(protocol, packet.streamId);
      return {
        packet,
        protocol,
        streamId: packet.streamId,
      };
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

  useSelectedPacketDetail({
    selectedPacketId,
    shouldLoad: shouldLoadSelectedPacketDetail(selectedPacketId, selectedPacketDetail),
    captureTaskScopeRef,
    loadPacket: (packetId, signal) => bridge.getPacket(packetId, signal),
    setSelectedPacketDetail,
  });

  useSelectedPacketArtifact<string>({
    selectedPacketId,
    selectedPacket,
    shouldLoad: shouldLoadSelectedPacketArtifacts(selectedPacketId, selectedPacket),
    taskKey: "packet-raw-hex",
    captureTaskScopeRef,
    loadArtifact: (packetId, signal) => bridge.getPacketRawHex(packetId, signal),
    setValue: setSelectedPacketRawHex,
    resetValue: "",
  });

  useSelectedPacketArtifact<Record<string, unknown> | null>({
    selectedPacketId,
    selectedPacket,
    shouldLoad: shouldLoadSelectedPacketArtifacts(selectedPacketId, selectedPacket),
    taskKey: "packet-layers",
    captureTaskScopeRef,
    loadArtifact: (packetId, signal) => bridge.getPacketLayers(packetId, signal),
    setValue: setSelectedPacketLayers,
    resetValue: null,
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
        const opened = filePath
          ? (buildOpenedCaptureFromPath(filePath) ?? (await bridge.openPcapFile()))
          : await bridge.openPcapFile();
        pendingCapture = opened;

        await prepareForCaptureReplacement();
        setIsFilterLoading(false);
        setPacketPageError("");
        resetPreloadCounterState({
          preloadProcessedRef,
          preloadTotalRef,
          setPreloadProcessed,
          setPreloadTotal,
        });
        startCaptureParseRuntime({
          parseFinishedRef,
          parseErrorRef,
          preloadingRef,
          setIsPreloadingCapture,
        });
        setCaptureTransaction(
          createPendingCaptureTransactionStatus(opened.fileName, opened.filePath, hadActiveCapture),
        );
        rememberRecentCapture(buildRecentCapture(opened, new Date().toISOString()));

        const startTask = captureTaskScopeRef.current.beginTask("capture-start");
        try {
          await bridge.startStreamingPackets(opened.filePath, "", startTask.signal);
          if (!startTask.isCurrent()) return false;
        } finally {
          startTask.finish();
        }
        if (captureSeq !== captureSeqRef.current) return false;
        setBackendStatus(getCapturePreloadWorkingStatus(opened.fileName));

        const waitDeadline = Date.now() + CAPTURE_PRELOAD_TIMEOUT_MS;
        let firstPageLoaded = false;
        let activeCaptureConfirmed = false;
        let validatedFirstPage: Pick<
          Awaited<ReturnType<typeof bridge.listPacketsPage>>,
          "items" | "total" | "hasMore"
        > | null = null;
        while (Date.now() < waitDeadline && captureSeq === captureSeqRef.current) {
          const probeLimit = firstPageLoaded ? 1 : PAGE_SIZE;
          const probeTask = captureTaskScopeRef.current.beginTask("preload-page");
          try {
            const [probePage, captureStatus] = await Promise.all([
              bridge.listPacketsPage(0, probeLimit, effectiveFilter, probeTask.signal),
              bridge.getCaptureStatus(probeTask.signal).catch(() => null),
            ]);
            if (!probeTask.isCurrent() || captureSeq !== captureSeqRef.current) return false;
            activeCaptureConfirmed = isCommittedCaptureStatusForPath(captureStatus, opened.filePath);
            if (activeCaptureConfirmed && probePage.total > 0) {
              setTotalPackets(probePage.total);
              if (preloadTotalRef.current <= 0) {
                setPreloadProcessed(probePage.total);
                preloadProcessedRef.current = probePage.total;
              }
            }
            if (!firstPageLoaded && activeCaptureConfirmed && probePage.total > 0) {
              validatedFirstPage = {
                items: probePage.items,
                total: probePage.total,
                hasMore: probePage.hasMore,
              };
              firstPageLoaded = true;
            }
          } finally {
            probeTask.finish();
          }

          if (activeCaptureConfirmed && firstPageLoaded) {
            break;
          }
          if (parseFinishedRef.current) {
            break;
          }

          await waitForCaptureSignal(firstPageLoaded ? PRELOAD_SIGNAL_WAIT_MS : PRELOAD_POLL_INTERVAL_MS);
        }

        if (captureSeq !== captureSeqRef.current) return false;
        const probeTask = captureTaskScopeRef.current.beginTask("preload-page");
        let probePage: Awaited<ReturnType<typeof bridge.listPacketsPage>>;
        let captureStatus: Awaited<ReturnType<typeof bridge.getCaptureStatus>> | null = null;
        try {
          [probePage, captureStatus] = await Promise.all([
            bridge.listPacketsPage(0, firstPageLoaded ? 1 : PAGE_SIZE, effectiveFilter, probeTask.signal),
            bridge.getCaptureStatus(probeTask.signal).catch(() => null),
          ]);
          if (!probeTask.isCurrent() || captureSeq !== captureSeqRef.current) return false;
        } finally {
          probeTask.finish();
        }
        activeCaptureConfirmed = isCommittedCaptureStatusForPath(captureStatus, opened.filePath);
        if (!firstPageLoaded && activeCaptureConfirmed && probePage.total > 0) {
          validatedFirstPage = {
            items: probePage.items,
            total: probePage.total,
            hasMore: probePage.hasMore,
          };
          firstPageLoaded = true;
        }
        if (probePage.total === 0 && parseFinishedRef.current) {
          throw new Error(getCaptureEmptyParseError(parseErrorRef.current));
        }
        if (!activeCaptureConfirmed || !firstPageLoaded) {
          throw new Error(getCapturePreloadTimeoutError());
        }
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
          hasMorePackets: true,
        });
        resetStreamRuntimeRefs({
          httpCache: httpStreamCacheRef.current,
          tcpCache: tcpStreamCacheRef.current,
          udpCache: udpStreamCacheRef.current,
          httpPrefetchInFlight: httpPrefetchInFlightRef.current,
          tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
          udpPrefetchInFlight: udpPrefetchInFlightRef.current,
          switchSequences: streamSwitchSequencesRef.current,
          switchDurationsRef: streamSwitchDurationsRef,
          switchHitsRef: streamSwitchHitsRef,
        });
        setStreamSwitchMetrics(EMPTY_SWITCH_METRICS);
        resetAnalysisState();
        setFileMeta(buildCaptureFileMeta(opened));
        setCaptureRevision((prev) => prev + 1);
        activeCapturePathRef.current = opened.filePath;
        if (validatedFirstPage) {
          commitPacketPage(0, validatedFirstPage);
        }
        await refreshStreamIndex();
        if (captureSeq !== captureSeqRef.current) return false;
        setCaptureTransaction(createIdleCaptureTransactionStatus(true));
        setBackendStatus(getCapturePreloadDoneStatus(opened.fileName));
        void refreshAnalysisResult({
          capturePath: opened.filePath,
          quietSuccess: true,
        });
        return true;
      } catch (error) {
        if (isAbortLikeError(error)) {
          return false;
        }
        if (captureSeq === captureSeqRef.current) {
          const message = getCaptureOpenErrorMessage(error);
          const normalizedMessage = message || "打开文件失败";
          const reason =
            normalizedMessage === getCapturePreloadTimeoutError()
              ? "preload_timeout"
              : normalizedMessage === getCaptureEmptyParseError("")
                ? "empty_parse"
                : hadActiveCapture
                  ? "switch_failed"
                  : "open_failed";
          setCaptureTransaction(
            createFailedCaptureTransactionStatus(
              reason,
              normalizedMessage,
              pendingCapture?.fileName ?? (filePath?.trim() || ""),
              pendingCapture?.filePath ?? (filePath?.trim() || ""),
              hadActiveCapture,
            ),
          );
          setBackendStatus(normalizedMessage);
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
      if (value !== undefined) {
        setDisplayFilter(nextFilter);
      }

      void runPacketFilterWorkflow({
        filter: nextFilter,
        shouldRun: Boolean(activeCapturePathRef.current && backendConnected && !isPreloadingCapture),
        pollUntilSettled: true,
        filterSeqRef,
        loadPacketPage,
        resetPacketViewport,
        setIsFilterLoading,
        setPacketPageError,
        setBackendStatus,
      });
    },
    [backendConnected, displayFilter, isPreloadingCapture, loadPacketPage, resetPacketViewport],
  );

  const clearFilter = useCallback(() => {
    setDisplayFilter("");

    void runPacketFilterWorkflow({
      filter: "",
      shouldRun: Boolean(activeCapturePathRef.current && backendConnected && !isPreloadingCapture),
      pollUntilSettled: false,
      filterSeqRef,
      loadPacketPage,
      resetPacketViewport,
      setIsFilterLoading,
      setPacketPageError,
      setBackendStatus,
    });
  }, [backendConnected, isPreloadingCapture, loadPacketPage, resetPacketViewport]);

  const selectPacket = useCallback((id: number) => {
    setSelectedPacketId(id);
    setSelectedPacketDetail((prev) => keepSelectedPacketDetailForId(prev, id));
  }, []);

  const openCapture = useCallback(
    async (filePath?: string) => {
      setDisplayFilter("");
      return startCapture(filePath, "");
    },
    [startCapture],
  );

  const stopCapture = useCallback(async () => {
    captureSeqRef.current += 1;
    filterSeqRef.current += 1;
    finishCaptureParseRuntime({
      parseFinishedRef,
      parseErrorRef,
      preloadingRef,
      setIsPreloadingCapture,
    });
    setIsFilterLoading(false);
    cancelAllFrontendCaptureTasks();
    wakeCaptureWaiters();
    clearCaptureUiState();
    threatAnalysisSeqRef.current += 1;
    setBackendStatus(getCaptureStopRequestStatus(backendConnected));
    if (!backendConnected) return;

    let closeError = "";
    try {
      await bridge.cancelMediaBatchTranscription().catch(() => null);
      await bridge.closeCapture();
    } catch (error) {
      closeError = getCaptureCloseErrorMessage(error);
    }
    setBackendStatus(getCaptureStopDoneStatus(closeError));
  }, [backendConnected, cancelAllFrontendCaptureTasks, clearCaptureUiState, wakeCaptureWaiters]);

  const protocolTree = useMemo(
    () =>
      selectedPacketLayers
        ? buildProtocolTreeFromLayers(selectedPacketLayers, selectedPacket)
        : buildProtocolTree(selectedPacket),
    [selectedPacketLayers, selectedPacket],
  );
  const hexDump = useMemo(() => buildHexDump(selectedPacket), [selectedPacket]);
  const currentPage = useMemo(() => getCurrentPacketPage(pageStart, PAGE_SIZE), [pageStart]);
  const totalPages = useMemo(() => getTotalPacketPages(totalPackets, PAGE_SIZE), [totalPackets]);

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

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return prettySize(bytes);
}
