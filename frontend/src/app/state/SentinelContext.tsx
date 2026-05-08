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
import type {
  BinaryStream,
  DecryptionConfig,
  HttpStream,
  Packet,
  RecentCapture,
  ToolRuntimeConfig,
  StreamSwitchMetrics,
} from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { isAbortLikeError, isOperationTimeoutError, withTimeout } from "../utils/asyncControl";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { useToolRuntime, readToolRuntimeConfig, writeToolRuntimeConfig } from "./hooks/useToolRuntime";
import { useSelectedPacketArtifact } from "./hooks/useSelectedPacketArtifact";
import { useSelectedPacketDetail } from "./hooks/useSelectedPacketDetail";
import { useSyncedRefValue } from "./hooks/useSyncedRefValue";
import {
  EMPTY_MEDIA_ANALYSIS_PROGRESS,
  EMPTY_THREAT_ANALYSIS_PROGRESS,
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
import {
  isProgressStatusMessage,
  shouldIgnoreCaptureErrorWithoutActiveCapture,
  shouldIgnoreCaptureStatusWithoutActiveCapture,
  shouldMarkParseErrorFromStatus,
  shouldMarkParseFinishedFromStatus,
  shouldResetMediaAnalysisFromError,
  shouldResetMediaAnalysisFromStatus,
  shouldResetThreatAnalysisFromError,
  shouldResetThreatAnalysisFromStatus,
} from "./backendStatusMessage";
import { readRecentCaptures, updateRecentCaptures, writeRecentCaptures } from "./recentCaptures";
import {
  getCurrentPacketPage,
  getNextPacketCursor,
  getPacketPageCursor,
  getPrevPacketCursor,
  getTotalPacketPages,
  normalizePacketCursor,
  normalizePacketId,
  packetPageHasPacket,
} from "./packetPagination";
import {
  keepSelectedPacketDetailForId,
  preserveSelectedPacketId,
  resolveSelectedPacket,
  shouldLoadSelectedPacketArtifacts,
  shouldLoadSelectedPacketDetail,
} from "./selectedPacketState";
import {
  PACKET_FILTER_POLL_INTERVAL_MS,
  PACKET_FILTER_POLL_TIMEOUT_MS,
  getPacketFilterDoneStatus,
  getPacketFilterPollingStatus,
  getPacketFilterWorkingStatus,
} from "./packetFilterStatus";
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
  PAGE_SIZE,
  PRELOAD_POLL_INTERVAL_MS,
  PRELOAD_SIGNAL_WAIT_MS,
  RAW_STREAM_PAGE_SIZE,
  STARTUP_TLS_CONFIG_TIMEOUT_MS,
  STARTUP_TOOL_RUNTIME_TIMEOUT_MS,
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
import { scheduleStreamPrefetch } from "./streamPrefetchScheduler";
import { commitProtocolStreamPayloadPatches } from "./streamPayloadPatch";
import {
  bumpAllStreamSwitchSequences,
  bumpStreamSwitchSequence,
  createStreamSwitchSequences,
  isLatestStreamSwitchSequence,
} from "./streamSwitchSequence";
import {
  clearStreamPrefetchInFlight,
  createEmptyStreamSwitchDurations,
  createEmptyStreamSwitchHits,
  resetStreamRuntimeRefs,
} from "./streamRuntimeReset";
import { recordStreamSwitchMetricSample } from "./streamSwitchMetrics";
import {
  waitForCaptureSignal as waitForCaptureSignalUtil,
  wakeCaptureWaiters as wakeCaptureWaitersUtil,
} from "./captureSignal";
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
  const [displayFilter, setDisplayFilter] = useState("");
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [selectedPacketDetail, setSelectedPacketDetail] = useState<Packet | null>(null);
  const [selectedPacketRawHex, setSelectedPacketRawHex] = useState("");
  const [selectedPacketLayers, setSelectedPacketLayers] = useState<Record<string, unknown> | null>(null);
  const [backendConnected, setBackendConnected] = useState(false);
  const [backendStatus, setBackendStatus] = useState("等待后端连接");
  const threatAnalysisSeqRef = useRef(0);
  const {
    threatHits,
    setThreatHits,
    isThreatAnalysisLoading,
    setIsThreatAnalysisLoading,
    threatAnalysisProgress,
    setThreatAnalysisProgress,
    extractedObjects,
    setExtractedObjects,
    mediaAnalysisProgress,
    setMediaAnalysisProgress,
    refreshAnalysisResult: refreshAnalysisResultImpl,
  } = useAnalysisProgress(threatAnalysisSeqRef);
  const {
    tsharkStatus,
    setTsharkStatus,
    isTSharkChecking,
    setIsTSharkChecking,
    toolRuntimeSnapshot,
    setToolRuntimeSnapshot,
    isToolRuntimeLoading,
    setIsToolRuntimeLoading,
    toolRuntimeCheckDegraded,
    setToolRuntimeCheckDegraded,
    setTSharkPath: setTSharkPathImpl,
    refreshToolRuntimeSnapshot: refreshToolRuntimeSnapshotImpl,
    saveToolRuntimeConfig: saveToolRuntimeConfigImpl,
  } = useToolRuntime();
  const [httpStream, setHttpStream] = useState<HttpStream>(EMPTY_HTTP_STREAM);
  const [tcpStream, setTcpStream] = useState<BinaryStream>(EMPTY_BINARY_STREAM);
  const [udpStream, setUdpStream] = useState<BinaryStream>(createEmptyUdpStream);
  const [streamIds, setStreamIds] = useState(createEmptyStreamIds);
  const [fileMeta, setFileMeta] = useState(createInitialCaptureFileMeta);
  const [captureRevision, setCaptureRevision] = useState(0);
  const [recentCaptures, setRecentCaptures] = useState<RecentCapture[]>(() => readRecentCaptures());
  const [decryptionConfig, setDecryptionConfig] = useState<DecryptionConfig>({
    sslKeyLogPath: "",
    privateKeyPath: "",
    privateKeyIpPort: "",
  });

  const refreshTimer = useRef<number | null>(null);
  const pageStartRef = useRef(0);
  const captureTaskScopeRef = useRef(createCaptureTaskScope());
  const packetPageSeqRef = useRef(0);
  const hasMorePacketsRef = useRef(false);
  const loadMoreScheduledRef = useRef<number | null>(null);
  const backendRetryTimerRef = useRef<number | null>(null);
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
  const httpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const tcpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const udpPrefetchInFlightRef = useRef<Set<number>>(new Set());
  const streamSwitchSequencesRef = useRef(createStreamSwitchSequences());
  const [streamSwitchMetrics, setStreamSwitchMetrics] = useState<StreamSwitchMetrics>(EMPTY_SWITCH_METRICS);
  const streamSwitchDurationsRef = useRef(createEmptyStreamSwitchDurations());
  const streamSwitchHitsRef = useRef(createEmptyStreamSwitchHits());

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
    captureTaskScopeRef.current.invalidate();
    packetPageSeqRef.current += 1;
    threatAnalysisSeqRef.current += 1;
    bumpAllStreamSwitchSequences(streamSwitchSequencesRef.current);
    clearStreamPrefetchInFlight({
      httpPrefetchInFlight: httpPrefetchInFlightRef.current,
      tcpPrefetchInFlight: tcpPrefetchInFlightRef.current,
      udpPrefetchInFlight: udpPrefetchInFlightRef.current,
    });
    if (loadMoreScheduledRef.current != null) {
      window.clearTimeout(loadMoreScheduledRef.current);
      loadMoreScheduledRef.current = null;
    }
    if (refreshTimer.current != null) {
      window.clearTimeout(refreshTimer.current);
      refreshTimer.current = null;
    }
    setIsPageLoading(false);
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
      hasMorePacketsRef.current = page.hasMore;
      setHasMorePackets(page.hasMore);
    },
    [],
  );

  const resetPacketViewport = useCallback(() => {
    cancelPacketPageLoad();
    pageStartRef.current = 0;
    setPageStart(0);
    setPackets([]);
    setTotalPackets(0);
    setHasPrevPackets(false);
    hasMorePacketsRef.current = false;
    setHasMorePackets(false);
    setSelectedPacketId(null);
    setSelectedPacketDetail(null);
    setSelectedPacketRawHex("");
    setSelectedPacketLayers(null);
  }, [cancelPacketPageLoad]);

  const clearCaptureUiState = useCallback(() => {
    setPackets([]);
    setTotalPackets(0);
    setPageStart(0);
    pageStartRef.current = 0;
    setPreloadProcessed(0);
    setPreloadTotal(0);
    preloadProcessedRef.current = 0;
    preloadTotalRef.current = 0;
    setHasPrevPackets(false);
    hasMorePacketsRef.current = false;
    setHasMorePackets(false);
    setSelectedPacketId(null);
    setSelectedPacketDetail(null);
    setSelectedPacketRawHex("");
    setSelectedPacketLayers(null);
    setThreatHits([]);
    setIsThreatAnalysisLoading(false);
    setThreatAnalysisProgress(EMPTY_THREAT_ANALYSIS_PROGRESS);
    setExtractedObjects([]);
    setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
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
    activeCapturePathRef.current = "";
    setCaptureRevision((prev) => prev + 1);
  }, []);

  const loadPacketPage = useCallback(
    async (cursor: number, filterOverride?: string, options?: { finishFilterLoading?: boolean }) => {
      if (!backendConnected || !activeCapturePathRef.current) return null;
      const requestSeq = ++packetPageSeqRef.current;
      const task = captureTaskScopeRef.current.beginTask("packet-page");
      setIsPageLoading(true);
      try {
        const safeCursor = normalizePacketCursor(cursor);
        const page = await bridge.listPacketsPage(safeCursor, PAGE_SIZE, filterOverride ?? displayFilter, task.signal);
        if (!task.isCurrent() || requestSeq !== packetPageSeqRef.current) {
          return null;
        }
        commitPacketPage(safeCursor, page);
        return page;
      } catch (error) {
        if (!task.isCurrent() || isAbortLikeError(error, task.signal)) {
          return null;
        }
        setBackendStatus(error instanceof Error ? error.message : "数据包加载失败");
        return null;
      } finally {
        const isCurrent = task.isCurrent();
        task.finish();
        if (isCurrent && requestSeq === packetPageSeqRef.current) {
          setIsPageLoading(false);
          if (options?.finishFilterLoading) {
            setIsFilterLoading(false);
          }
        }
      }
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

  const locatePacketById = useCallback(
    async (packetId: number, filterOverride?: string) => {
      const normalized = normalizePacketId(packetId);
      if (normalized <= 0 || !activeCapturePathRef.current) return null;
      const task = captureTaskScopeRef.current.beginTask("packet-locate");
      try {
        const effectiveFilter = filterOverride ?? displayFilter;
        const located = await bridge.locatePacketPage(normalized, PAGE_SIZE, effectiveFilter, task.signal);
        if (!task.isCurrent()) {
          return null;
        }
        if (!located.found) {
          setBackendStatus(`未找到数据包 #${normalized}`);
          return null;
        }
        if (filterOverride !== undefined) {
          setDisplayFilter(effectiveFilter);
        }
        const page = await loadPacketPage(located.cursor, effectiveFilter);
        if (!page) {
          return null;
        }
        if (!task.isCurrent()) {
          return null;
        }
        setSelectedPacketId(normalized);
        return page.items.find((item) => item.id === normalized) ?? null;
      } catch (error) {
        if (!task.isCurrent() || isAbortLikeError(error, task.signal)) {
          return null;
        }
        setBackendStatus(error instanceof Error ? error.message : "定位数据包失败");
        return null;
      } finally {
        task.finish();
      }
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
    preloadingRef.current = false;
    parseFinishedRef.current = true;
    parseErrorRef.current = "";
    setIsFilterLoading(false);
    setIsPreloadingCapture(false);
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

  const setTSharkPath = useCallback(
    async (path: string) => {
      await setTSharkPathImpl(path, backendConnected, setBackendStatus);
    },
    [setTSharkPathImpl, backendConnected],
  );

  const refreshToolRuntimeSnapshot = useCallback(async () => {
    return await refreshToolRuntimeSnapshotImpl(backendConnected);
  }, [refreshToolRuntimeSnapshotImpl, backendConnected]);

  const saveToolRuntimeConfig = useCallback(
    async (patch: Partial<ToolRuntimeConfig>) => {
      return await saveToolRuntimeConfigImpl(patch, backendConnected, setBackendStatus);
    },
    [saveToolRuntimeConfigImpl, backendConnected],
  );

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
    if (!backendConnected) return;
    const capturePath = activeCapturePathRef.current;
    if (!capturePath) return;
    const task = captureTaskScopeRef.current.beginTask("stream-index");
    try {
      const [httpIds, tcpIds, udpIds] = await Promise.all([
        bridge.listStreamIds("HTTP", task.signal),
        bridge.listStreamIds("TCP", task.signal),
        bridge.listStreamIds("UDP", task.signal),
      ]);
      if (!task.isCurrent() || activeCapturePathRef.current !== capturePath) {
        return;
      }
      setStreamIds({ http: httpIds, tcp: tcpIds, udp: udpIds });
    } catch (error) {
      if (!task.isCurrent() || isAbortLikeError(error, task.signal)) {
        return;
      }
      setBackendStatus("流索引刷新失败");
    } finally {
      task.finish();
    }
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
      if (!backendConnected || streamId < 0 || patches.length === 0) return;
      await bridge.updateStreamPayloads(protocol, streamId, patches);

      startTransition(() => {
        commitProtocolStreamPayloadPatches({
          protocol,
          streamId,
          patches,
          setHttpStream,
          setTcpStream,
          setUdpStream,
          httpCache: httpStreamCacheRef.current,
          tcpCache: tcpStreamCacheRef.current,
          udpCache: udpStreamCacheRef.current,
        });
      });
    },
    [backendConnected],
  );

  const scheduleLoadMoreRef = useRef(scheduleLoadMore);
  const refreshAnalysisResultRef = useRef(refreshAnalysisResult);
  const updateProgressFromStatusRef = useRef(updateProgressFromStatus);

  useSyncedRefValue(scheduleLoadMoreRef, scheduleLoadMore);
  useSyncedRefValue(refreshAnalysisResultRef, refreshAnalysisResult);
  useSyncedRefValue(updateProgressFromStatusRef, updateProgressFromStatus);

  useEffect(
    () => () => {
      captureTaskScopeRef.current.invalidate();
    },
    [],
  );

  useEffect(() => {
    let dispose: (() => void) | null = null;
    let cancelled = false;

    const clearBackendRetryTimer = () => {
      if (backendRetryTimerRef.current != null) {
        window.clearTimeout(backendRetryTimerRef.current);
        backendRetryTimerRef.current = null;
      }
    };

    const scheduleBackendRetry = (delayMs = 2000) => {
      clearBackendRetryTimer();
      backendRetryTimerRef.current = window.setTimeout(() => {
        void setup();
      }, delayMs);
    };

    const setup = async () => {
      if (cancelled) return;
      const available = await bridge.isAvailable();
      if (cancelled) return;
      if (!available) {
        setBackendConnected(false);
        const desktopStatus = await bridge.getDesktopBackendStatus().catch(() => "");
        const detail = desktopStatus.trim();
        if (detail && detail !== "not-started" && detail !== "starting") {
          setBackendStatus(detail);
        } else {
          setBackendStatus("桌面后端未连接，请启动或重启桌面应用");
        }
        scheduleBackendRetry();
        return;
      }

      clearBackendRetryTimer();
      setBackendConnected(true);
      setBackendStatus("后端已连接，等待打开文件");
      setIsTSharkChecking(true);
      setIsToolRuntimeLoading(true);
      setToolRuntimeCheckDegraded(false);

      try {
        const savedConfig = readToolRuntimeConfig();
        const snapshot = await withTimeout(
          bridge.updateToolRuntimeConfig(savedConfig),
          STARTUP_TOOL_RUNTIME_TIMEOUT_MS,
          "startup tool runtime check timed out",
        );
        setToolRuntimeSnapshot(snapshot);
        setTsharkStatus({
          available: snapshot.tshark.available,
          path: snapshot.tshark.path,
          message: snapshot.tshark.message,
          customPath: snapshot.tshark.customPath ?? "",
          usingCustomPath: snapshot.tshark.usingCustomPath,
        });
        if (!cancelled) {
          writeToolRuntimeConfig(snapshot.config);
        }
        if (!cancelled && snapshot.tshark.available && snapshot.tshark.message && snapshot.tshark.message !== "ok") {
          setBackendStatus(snapshot.tshark.message);
        }
        if (!cancelled && !snapshot.tshark.available) {
          setBackendStatus(snapshot.tshark.message || "未检测到 tshark，请先配置路径");
        }
      } catch (error) {
        if (!cancelled) {
          setToolRuntimeCheckDegraded(true);
          const prefix = isOperationTimeoutError(error) ? "运行时组件检测超时" : "运行时组件检测失败";
          setBackendStatus(`${prefix}，已先进入主界面；可在设置侧栏刷新状态`);
          setTsharkStatus((prev) => ({
            ...prev,
            message: `${prefix}，请稍后在设置侧栏刷新状态`,
          }));
        }
      } finally {
        if (!cancelled) {
          setIsTSharkChecking(false);
          setIsToolRuntimeLoading(false);
        }
      }

      try {
        const tls = await withTimeout(
          bridge.getTLSConfig(),
          STARTUP_TLS_CONFIG_TIMEOUT_MS,
          "startup TLS config check timed out",
        );
        if (tls) {
          setDecryptionConfig(tls);
        }
      } catch (error) {
        if (!isOperationTimeoutError(error)) {
          setBackendStatus("后端初始化失败");
        }
      }

      dispose = bridge.subscribeEvents({
        packet: (packet) => {
          setSelectedPacketId((prev) => preserveSelectedPacketId(prev, packet.id));
          if (preloadingRef.current) {
            return;
          }
          scheduleLoadMoreRef.current();

          if (refreshTimer.current) {
            window.clearTimeout(refreshTimer.current);
          }
          refreshTimer.current = window.setTimeout(() => {
            void refreshAnalysisResultRef.current();
          }, 500);
        },
        status: (message) => {
          const msg = message || "后端运行中";
          if (shouldIgnoreCaptureStatusWithoutActiveCapture(msg, Boolean(activeCapturePathRef.current))) {
            return;
          }
          if (isProgressStatusMessage(msg)) {
            updateProgressFromStatusRef.current(msg);
            wakeCaptureWaiters();
            return;
          }
          if (shouldMarkParseFinishedFromStatus(msg)) {
            parseFinishedRef.current = true;
            if (shouldMarkParseErrorFromStatus(msg)) {
              parseErrorRef.current = msg;
            }
          }
          if (shouldResetMediaAnalysisFromStatus(msg)) {
            setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
          }
          if (shouldResetThreatAnalysisFromStatus(msg)) {
            setThreatAnalysisProgress((prev) => (prev.phase === "complete" ? prev : EMPTY_THREAT_ANALYSIS_PROGRESS));
          }
          wakeCaptureWaiters();
          setBackendStatus(msg);
        },
        error: (message) => {
          const next = message || "后端事件异常";
          if (shouldIgnoreCaptureErrorWithoutActiveCapture(next, Boolean(activeCapturePathRef.current))) {
            return;
          }
          if (preloadingRef.current) {
            parseFinishedRef.current = true;
            parseErrorRef.current = next;
          }
          if (shouldResetMediaAnalysisFromError(next)) {
            setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
          }
          if (shouldResetThreatAnalysisFromError(next)) {
            setThreatAnalysisProgress(EMPTY_THREAT_ANALYSIS_PROGRESS);
            setIsThreatAnalysisLoading(false);
          }
          wakeCaptureWaiters();
          setBackendStatus(next);
        },
      });
    };

    void setup();

    return () => {
      cancelled = true;
      clearBackendRetryTimer();
      if (dispose) dispose();
      if (loadMoreScheduledRef.current != null) {
        window.clearTimeout(loadMoreScheduledRef.current);
      }
      if (refreshTimer.current) {
        window.clearTimeout(refreshTimer.current);
      }
    };
  }, []);

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
        return;
      }

      const captureSeq = ++captureSeqRef.current;
      filterSeqRef.current += 1;
      const effectiveFilter = filterOverride ?? displayFilter;

      try {
        const opened = filePath
          ? (buildOpenedCaptureFromPath(filePath) ?? (await bridge.openPcapFile()))
          : await bridge.openPcapFile();

        await prepareForCaptureReplacement();
        setIsFilterLoading(false);
        setPackets([]);
        setTotalPackets(0);
        setPageStart(0);
        setPreloadProcessed(0);
        setPreloadTotal(0);
        preloadProcessedRef.current = 0;
        preloadTotalRef.current = 0;
        setIsPreloadingCapture(true);
        pageStartRef.current = 0;
        setHasPrevPackets(false);
        hasMorePacketsRef.current = true;
        parseFinishedRef.current = false;
        parseErrorRef.current = "";
        preloadingRef.current = true;
        setHasMorePackets(true);
        setSelectedPacketId(null);
        setSelectedPacketDetail(null);
        setSelectedPacketRawHex("");
        setSelectedPacketLayers(null);
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
        setThreatHits([]);
        setIsThreatAnalysisLoading(false);
        setThreatAnalysisProgress(EMPTY_THREAT_ANALYSIS_PROGRESS);
        setExtractedObjects([]);
        setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
        setFileMeta(buildCaptureFileMeta(opened));
        setCaptureRevision((prev) => prev + 1);
        activeCapturePathRef.current = opened.filePath;
        rememberRecentCapture(buildRecentCapture(opened, new Date().toISOString()));

        const startTask = captureTaskScopeRef.current.beginTask("capture-start");
        try {
          await bridge.startStreamingPackets(opened.filePath, "", startTask.signal);
          if (!startTask.isCurrent()) return;
        } finally {
          startTask.finish();
        }
        if (captureSeq !== captureSeqRef.current) return;
        setBackendStatus(getCapturePreloadWorkingStatus(opened.fileName));

        const waitDeadline = Date.now() + CAPTURE_PRELOAD_TIMEOUT_MS;
        let firstPageLoaded = false;
        while (Date.now() < waitDeadline && captureSeq === captureSeqRef.current) {
          const probeLimit = firstPageLoaded ? 1 : PAGE_SIZE;
          const probeTask = captureTaskScopeRef.current.beginTask("preload-page");
          try {
            const probePage = await bridge.listPacketsPage(0, probeLimit, effectiveFilter, probeTask.signal);
            if (!probeTask.isCurrent() || captureSeq !== captureSeqRef.current) return;
            if (probePage.total > 0) {
              setTotalPackets(probePage.total);
              if (preloadTotalRef.current <= 0) {
                setPreloadProcessed(probePage.total);
                preloadProcessedRef.current = probePage.total;
              }
            }
            if (!firstPageLoaded && probePage.total > 0) {
              commitPacketPage(0, {
                items: probePage.items,
                total: probePage.total,
                hasMore: probePage.hasMore,
              });
              firstPageLoaded = true;
            }
          } finally {
            probeTask.finish();
          }

          if (parseFinishedRef.current) {
            break;
          }

          await waitForCaptureSignal(firstPageLoaded ? PRELOAD_SIGNAL_WAIT_MS : PRELOAD_POLL_INTERVAL_MS);
        }

        if (captureSeq !== captureSeqRef.current) return;
        const probeTask = captureTaskScopeRef.current.beginTask("preload-page");
        let probePage: Awaited<ReturnType<typeof bridge.listPacketsPage>>;
        try {
          probePage = await bridge.listPacketsPage(0, 1, effectiveFilter, probeTask.signal);
          if (!probeTask.isCurrent() || captureSeq !== captureSeqRef.current) return;
        } finally {
          probeTask.finish();
        }
        if (probePage.total === 0 && parseFinishedRef.current) {
          throw new Error(getCaptureEmptyParseError(parseErrorRef.current));
        }
        if (!parseFinishedRef.current && Date.now() >= waitDeadline) {
          throw new Error(getCapturePreloadTimeoutError());
        }
        if (!firstPageLoaded && probePage.total > 0) {
          await loadPacketPage(0, effectiveFilter);
        }
        await refreshStreamIndex();
        if (captureSeq !== captureSeqRef.current) return;
        setBackendStatus(getCapturePreloadDoneStatus(opened.fileName));
        void refreshAnalysisResult({
          capturePath: opened.filePath,
          quietSuccess: true,
        });
      } catch (error) {
        if (isAbortLikeError(error)) {
          return;
        }
        if (captureSeq === captureSeqRef.current) {
          setBackendStatus(getCaptureOpenErrorMessage(error));
        }
      } finally {
        if (captureSeq === captureSeqRef.current) {
          preloadingRef.current = false;
          setIsPreloadingCapture(false);
          wakeCaptureWaiters();
        }
      }
    },
    [
      backendConnected,
      commitPacketPage,
      displayFilter,
      prepareForCaptureReplacement,
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

      if (activeCapturePathRef.current && backendConnected && !isPreloadingCapture) {
        const filterSeq = ++filterSeqRef.current;
        setIsFilterLoading(true);
        resetPacketViewport();
        setBackendStatus(getPacketFilterWorkingStatus(nextFilter));
        void (async () => {
          let page = await loadPacketPage(0, nextFilter);
          const deadline = Date.now() + PACKET_FILTER_POLL_TIMEOUT_MS;
          while (filterSeq === filterSeqRef.current && page?.filtering && Date.now() < deadline) {
            setBackendStatus(getPacketFilterPollingStatus(nextFilter));
            await new Promise((resolve) => window.setTimeout(resolve, PACKET_FILTER_POLL_INTERVAL_MS));
            page = await loadPacketPage(0, nextFilter);
          }
          if (filterSeq === filterSeqRef.current) {
            setIsFilterLoading(false);
            setBackendStatus(getPacketFilterDoneStatus(nextFilter));
          }
        })();
      }
    },
    [backendConnected, displayFilter, isPreloadingCapture, loadPacketPage, resetPacketViewport],
  );

  const clearFilter = useCallback(() => {
    setDisplayFilter("");

    if (activeCapturePathRef.current && backendConnected && !isPreloadingCapture) {
      const filterSeq = ++filterSeqRef.current;
      setIsFilterLoading(true);
      resetPacketViewport();
      setBackendStatus(getPacketFilterWorkingStatus(""));
      void loadPacketPage(0, "").finally(() => {
        if (filterSeq === filterSeqRef.current) {
          setIsFilterLoading(false);
          setBackendStatus(getPacketFilterDoneStatus(""));
        }
      });
    }
  }, [backendConnected, isPreloadingCapture, loadPacketPage, resetPacketViewport]);

  const selectPacket = useCallback((id: number) => {
    setSelectedPacketId(id);
    setSelectedPacketDetail((prev) => keepSelectedPacketDetailForId(prev, id));
  }, []);

  const updateDecryptionConfig = useCallback(
    (patch: Partial<DecryptionConfig>) => {
      setDecryptionConfig((prev) => {
        const next = { ...prev, ...patch };
        if (backendConnected) {
          void bridge.updateTLSConfig(next).catch(() => setBackendStatus("TLS 配置更新失败"));
        }
        return next;
      });
    },
    [backendConnected],
  );

  const openCapture = useCallback(
    async (filePath?: string) => {
      setDisplayFilter("");
      await startCapture(filePath, "");
    },
    [startCapture],
  );

  const stopCapture = useCallback(async () => {
    captureSeqRef.current += 1;
    filterSeqRef.current += 1;
    preloadingRef.current = false;
    parseFinishedRef.current = true;
    parseErrorRef.current = "";
    setIsFilterLoading(false);
    setIsPreloadingCapture(false);
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
      loadMorePackets,
      loadPrevPackets,
      jumpToPage,
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
      loadMorePackets,
      loadPrevPackets,
      jumpToPage,
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
