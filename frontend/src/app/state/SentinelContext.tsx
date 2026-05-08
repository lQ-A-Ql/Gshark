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
import {
  buildHexDump,
  buildProtocolTree,
  buildProtocolTreeFromLayers,
} from "../core/engine";
import type {
  BinaryStream,
  DecryptionConfig,
  HttpStream,
  Packet,
  RecentCapture,
  ToolRuntimeConfig,
  StreamProtocol,
  StreamSwitchMetrics,
} from "../core/types";
import { bridge } from "../integrations/wailsBridge";
import { isAbortLikeError, isOperationTimeoutError, withTimeout } from "../utils/asyncControl";
import { createCaptureTaskScope } from "../utils/captureTaskScope";
import { useToolRuntime, readToolRuntimeConfig, writeToolRuntimeConfig } from "./hooks/useToolRuntime";
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
import { MAX_RECENT_CAPTURES, readRecentCaptures, writeRecentCaptures } from "./recentCaptures";
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
  SWITCH_SAMPLE_LIMIT,
  applyStreamChunkPatches,
  buildLoadingBinaryStream,
  buildLoadingHttpStream,
  buildSwitchStat,
  isFastPathLoad,
  markCachedLoad,
  prettySize,
} from "./streamState";
import { waitForCaptureSignal as waitForCaptureSignalUtil, wakeCaptureWaiters as wakeCaptureWaitersUtil } from "./captureSignal";
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
    threatHits, setThreatHits,
    isThreatAnalysisLoading, setIsThreatAnalysisLoading,
    threatAnalysisProgress, setThreatAnalysisProgress,
    extractedObjects, setExtractedObjects,
    mediaAnalysisProgress, setMediaAnalysisProgress,
    refreshAnalysisResult: refreshAnalysisResultImpl,
  } = useAnalysisProgress(threatAnalysisSeqRef);
  const {
    tsharkStatus, setTsharkStatus,
    isTSharkChecking, setIsTSharkChecking,
    toolRuntimeSnapshot, setToolRuntimeSnapshot,
    isToolRuntimeLoading, setIsToolRuntimeLoading,
    toolRuntimeCheckDegraded, setToolRuntimeCheckDegraded,
    setTSharkPath: setTSharkPathImpl,
    refreshToolRuntimeSnapshot: refreshToolRuntimeSnapshotImpl,
    saveToolRuntimeConfig: saveToolRuntimeConfigImpl,
  } = useToolRuntime();
  const [httpStream, setHttpStream] = useState<HttpStream>(EMPTY_HTTP_STREAM);
  const [tcpStream, setTcpStream] = useState<BinaryStream>(EMPTY_BINARY_STREAM);
  const [udpStream, setUdpStream] = useState<BinaryStream>({ ...EMPTY_BINARY_STREAM, protocol: "UDP" });
  const [streamIds, setStreamIds] = useState<{ http: number[]; tcp: number[]; udp: number[] }>({
    http: [],
    tcp: [],
    udp: [],
  });
  const [fileMeta, setFileMeta] = useState({
    name: "",
    sizeBytes: 0,
    path: "",
  });
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
  const httpSwitchSeqRef = useRef(0);
  const tcpSwitchSeqRef = useRef(0);
  const udpSwitchSeqRef = useRef(0);
  const [streamSwitchMetrics, setStreamSwitchMetrics] = useState<StreamSwitchMetrics>(EMPTY_SWITCH_METRICS);
  const streamSwitchDurationsRef = useRef<Record<"ALL" | StreamProtocol, number[]>>({
    ALL: [],
    HTTP: [],
    TCP: [],
    UDP: [],
  });
  const streamSwitchHitsRef = useRef<Record<"ALL" | StreamProtocol, number>>({
    ALL: 0,
    HTTP: 0,
    TCP: 0,
    UDP: 0,
  });

  const recordStreamSwitchMetric = useCallback((protocol: StreamProtocol, elapsedMs: number, cacheHit: boolean) => {
    const elapsed = Number.isFinite(elapsedMs) ? Math.max(0, elapsedMs) : 0;
    const appendSample = (bucket: "ALL" | StreamProtocol) => {
      const arr = streamSwitchDurationsRef.current[bucket];
      arr.push(elapsed);
      if (arr.length > SWITCH_SAMPLE_LIMIT) {
        arr.splice(0, arr.length - SWITCH_SAMPLE_LIMIT);
      }
      if (cacheHit) {
        streamSwitchHitsRef.current[bucket] += 1;
      }
    };

    appendSample("ALL");
    appendSample(protocol);

    setStreamSwitchMetrics({
      overall: buildSwitchStat(streamSwitchDurationsRef.current.ALL, streamSwitchHitsRef.current.ALL),
      byProtocol: {
        HTTP: buildSwitchStat(streamSwitchDurationsRef.current.HTTP, streamSwitchHitsRef.current.HTTP),
        TCP: buildSwitchStat(streamSwitchDurationsRef.current.TCP, streamSwitchHitsRef.current.TCP),
        UDP: buildSwitchStat(streamSwitchDurationsRef.current.UDP, streamSwitchHitsRef.current.UDP),
      },
    });
  }, []);

  const cancelAllFrontendCaptureTasks = useCallback(() => {
    captureTaskScopeRef.current.invalidate();
    packetPageSeqRef.current += 1;
    threatAnalysisSeqRef.current += 1;
    httpSwitchSeqRef.current += 1;
    tcpSwitchSeqRef.current += 1;
    udpSwitchSeqRef.current += 1;
    httpPrefetchInFlightRef.current.clear();
    tcpPrefetchInFlightRef.current.clear();
    udpPrefetchInFlightRef.current.clear();
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

  const commitPacketPage = useCallback((safeCursor: number, page: { items: Packet[]; total: number; hasMore: boolean }) => {
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
  }, []);

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
    setUdpStream({ ...EMPTY_BINARY_STREAM, protocol: "UDP" });
    setStreamIds({ http: [], tcp: [], udp: [] });
    httpStreamCacheRef.current.clear();
    tcpStreamCacheRef.current.clear();
    udpStreamCacheRef.current.clear();
    httpPrefetchInFlightRef.current.clear();
    tcpPrefetchInFlightRef.current.clear();
    udpPrefetchInFlightRef.current.clear();
    streamSwitchDurationsRef.current = {
      ALL: [],
      HTTP: [],
      TCP: [],
      UDP: [],
    };
    streamSwitchHitsRef.current = {
      ALL: 0,
      HTTP: 0,
      TCP: 0,
      UDP: 0,
    };
    setStreamSwitchMetrics(EMPTY_SWITCH_METRICS);
    setFileMeta({
      name: "未打开文件",
      sizeBytes: 0,
      path: "",
    });
    activeCapturePathRef.current = "";
    setCaptureRevision((prev) => prev + 1);
  }, []);

  const loadPacketPage = useCallback(async (
    cursor: number,
    filterOverride?: string,
    options?: { finishFilterLoading?: boolean },
  ) => {
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
  }, [backendConnected, commitPacketPage, displayFilter]);

  const loadMorePackets = useCallback(async () => {
    const next = getNextPacketCursor(pageStartRef.current, PAGE_SIZE);
    await loadPacketPage(next);
  }, [loadPacketPage]);

  const loadPrevPackets = useCallback(async () => {
    const prev = getPrevPacketCursor(pageStartRef.current, PAGE_SIZE);
    await loadPacketPage(prev);
  }, [loadPacketPage]);

  const jumpToPage = useCallback(async (page: number) => {
    const cursor = getPacketPageCursor(page, totalPackets, PAGE_SIZE);
    await loadPacketPage(cursor);
  }, [loadPacketPage, totalPackets]);

  const locatePacketById = useCallback(async (packetId: number, filterOverride?: string) => {
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
  }, [displayFilter, loadPacketPage]);

  const scheduleLoadMore = useCallback((delayMs = 120) => {
    if (loadMoreScheduledRef.current != null) return;
    loadMoreScheduledRef.current = window.setTimeout(() => {
      loadMoreScheduledRef.current = null;
      void loadPacketPage(pageStartRef.current);
    }, delayMs);
  }, [loadPacketPage]);

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

  const waitForCaptureSignal = useCallback((delayMs: number) => waitForCaptureSignalUtil(captureWaitersRef.current, delayMs), []);

  useEffect(() => {
    hasMorePacketsRef.current = hasMorePackets;
  }, [hasMorePackets]);

  const rememberRecentCapture = useCallback((entry: RecentCapture) => {
    setRecentCaptures((prev) => {
      const next = [
        entry,
        ...prev.filter((item) => item.path !== entry.path),
      ].slice(0, MAX_RECENT_CAPTURES);
      writeRecentCaptures(next);
      return next;
    });
  }, []);

  const setTSharkPath = useCallback(async (path: string) => {
    await setTSharkPathImpl(path, backendConnected, setBackendStatus);
  }, [setTSharkPathImpl, backendConnected]);

  const refreshToolRuntimeSnapshot = useCallback(async () => {
    return await refreshToolRuntimeSnapshotImpl(backendConnected);
  }, [refreshToolRuntimeSnapshotImpl, backendConnected]);

  const saveToolRuntimeConfig = useCallback(async (patch: Partial<ToolRuntimeConfig>) => {
    return await saveToolRuntimeConfigImpl(patch, backendConnected, setBackendStatus);
  }, [saveToolRuntimeConfigImpl, backendConnected]);

  const filteredPackets = useMemo(() => packets, [packets]);

  const selectedPacket = useMemo(
    () => resolveSelectedPacket(filteredPackets, selectedPacketId, selectedPacketDetail),
    [filteredPackets, selectedPacketDetail, selectedPacketId],
  );

  const refreshAnalysisResult = useCallback(async (
    options?: {
      capturePath?: string;
      quietSuccess?: boolean;
    },
  ) => {
    await refreshAnalysisResultImpl({
      ...options,
      backendConnected,
      activeCapturePath: activeCapturePathRef.current,
      captureTaskScope: captureTaskScopeRef.current,
      setBackendStatus,
    });
  }, [refreshAnalysisResultImpl, backendConnected]);

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

  const prefetchAdjacentStreams = useCallback((protocol: "HTTP" | "TCP" | "UDP", currentStreamId: number) => {
    if (!backendConnected || !activeCapturePathRef.current || currentStreamId < 0 || STREAM_PREFETCH_LIMIT <= 0) return;

    const ids = protocol === "HTTP" ? streamIds.http : protocol === "TCP" ? streamIds.tcp : streamIds.udp;
    const idx = ids.findIndex((id) => id === currentStreamId);
    if (idx < 0) return;

    const neighbors = [ids[idx + 1], ids[idx - 1]]
      .filter((id): id is number => Number.isFinite(id) && id > 0)
      .slice(0, STREAM_PREFETCH_LIMIT);
    for (const targetId of neighbors) {
      if (protocol === "HTTP") {
        if (httpStreamCacheRef.current.has(targetId) || httpPrefetchInFlightRef.current.has(targetId)) continue;
        if (httpPrefetchInFlightRef.current.size >= 2) continue;
        const task = captureTaskScopeRef.current.beginTask(`prefetch-http-${targetId}`);
        httpPrefetchInFlightRef.current.add(targetId);
        void bridge
          .getHttpStream(targetId, task.signal)
          .then((http) => {
            if (task.isCurrent()) {
              httpStreamCacheRef.current.set(http.id, http);
            }
          })
          .catch(() => {
            // Prefetch is opportunistic; failures and aborts should not surface in UI.
          })
          .finally(() => {
            task.finish();
            httpPrefetchInFlightRef.current.delete(targetId);
          });
        continue;
      }

      if (protocol === "TCP") {
        if (tcpStreamCacheRef.current.has(targetId) || tcpPrefetchInFlightRef.current.has(targetId)) continue;
        if (tcpPrefetchInFlightRef.current.size >= 2) continue;
        const task = captureTaskScopeRef.current.beginTask(`prefetch-tcp-${targetId}`);
        tcpPrefetchInFlightRef.current.add(targetId);
        void bridge
          .getRawStreamPage("TCP", targetId, 0, RAW_STREAM_PAGE_SIZE, task.signal)
          .then((raw) => {
            if (task.isCurrent()) {
              tcpStreamCacheRef.current.set(raw.id, raw);
            }
          })
          .catch(() => {
            // Prefetch is opportunistic; failures and aborts should not surface in UI.
          })
          .finally(() => {
            task.finish();
            tcpPrefetchInFlightRef.current.delete(targetId);
          });
        continue;
      }

      if (udpStreamCacheRef.current.has(targetId) || udpPrefetchInFlightRef.current.has(targetId)) continue;
      if (udpPrefetchInFlightRef.current.size >= 2) continue;
      const task = captureTaskScopeRef.current.beginTask(`prefetch-udp-${targetId}`);
      udpPrefetchInFlightRef.current.add(targetId);
      void bridge
        .getRawStreamPage("UDP", targetId, 0, RAW_STREAM_PAGE_SIZE, task.signal)
        .then((raw) => {
          if (task.isCurrent()) {
            udpStreamCacheRef.current.set(raw.id, raw);
          }
        })
        .catch(() => {
          // Prefetch is opportunistic; failures and aborts should not surface in UI.
        })
        .finally(() => {
          task.finish();
          udpPrefetchInFlightRef.current.delete(targetId);
        });
    }
  }, [backendConnected, streamIds.http, streamIds.tcp, streamIds.udp]);

  const setActiveStream = useCallback(async (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => {
    if (!backendConnected || !activeCapturePathRef.current || streamId < 0) return;
    const startedAt = typeof performance !== "undefined" ? performance.now() : Date.now();
    let cacheHit = false;

    const task = captureTaskScopeRef.current.beginTask(`${protocol.toLowerCase()}-stream`);

    const requestSeq = protocol === "HTTP"
      ? ++httpSwitchSeqRef.current
      : protocol === "TCP"
        ? ++tcpSwitchSeqRef.current
        : ++udpSwitchSeqRef.current;

    const isLatest = () => {
      if (!task.isCurrent()) return false;
      if (protocol === "HTTP") return requestSeq === httpSwitchSeqRef.current;
      if (protocol === "TCP") return requestSeq === tcpSwitchSeqRef.current;
      return requestSeq === udpSwitchSeqRef.current;
    };

    try {
      if (protocol === "HTTP") {
        const cached = httpStreamCacheRef.current.get(streamId);
        if (cached) {
          if (!isLatest()) return;
          const next = markCachedLoad(cached);
          cacheHit = true;
          startTransition(() => {
            setHttpStream(next);
          });
          const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;
          recordStreamSwitchMetric("HTTP", elapsed, cacheHit);
          prefetchAdjacentStreams("HTTP", streamId);
          return;
        }
        startTransition(() => {
          setHttpStream(buildLoadingHttpStream(streamId));
        });
        const http = await bridge.getHttpStream(streamId, task.signal);
        if (!isLatest()) return;
        httpStreamCacheRef.current.set(http.id, http);
        startTransition(() => {
          setHttpStream(http);
        });
        const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;
        recordStreamSwitchMetric("HTTP", elapsed, isFastPathLoad(http.loadMeta));
        prefetchAdjacentStreams("HTTP", streamId);
        return;
      }
      if (protocol === "TCP") {
        const cached = tcpStreamCacheRef.current.get(streamId);
        if (cached) {
          if (!isLatest()) return;
          const next = markCachedLoad(cached);
          cacheHit = true;
          startTransition(() => {
            setTcpStream(next);
          });
          const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;
          recordStreamSwitchMetric("TCP", elapsed, cacheHit);
          prefetchAdjacentStreams("TCP", streamId);
          return;
        }
        startTransition(() => {
          setTcpStream(buildLoadingBinaryStream("TCP", streamId));
        });
      }
      if (protocol === "UDP") {
        const cached = udpStreamCacheRef.current.get(streamId);
        if (cached) {
          if (!isLatest()) return;
          const next = markCachedLoad(cached);
          cacheHit = true;
          startTransition(() => {
            setUdpStream(next);
          });
          const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;
          recordStreamSwitchMetric("UDP", elapsed, cacheHit);
          prefetchAdjacentStreams("UDP", streamId);
          return;
        }
        startTransition(() => {
          setUdpStream(buildLoadingBinaryStream("UDP", streamId));
        });
      }
      const raw = await bridge.getRawStreamPage(protocol, streamId, 0, RAW_STREAM_PAGE_SIZE, task.signal);
      if (!isLatest()) return;
      if (protocol === "TCP") {
        tcpStreamCacheRef.current.set(raw.id, raw);
        startTransition(() => {
          setTcpStream(raw);
        });
        const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;
        recordStreamSwitchMetric("TCP", elapsed, isFastPathLoad(raw.loadMeta));
        prefetchAdjacentStreams("TCP", streamId);
      } else {
        udpStreamCacheRef.current.set(raw.id, raw);
        startTransition(() => {
          setUdpStream(raw);
        });
        const elapsed = (typeof performance !== "undefined" ? performance.now() : Date.now()) - startedAt;
        recordStreamSwitchMetric("UDP", elapsed, isFastPathLoad(raw.loadMeta));
        prefetchAdjacentStreams("UDP", streamId);
      }
    } catch (error) {
      if (!isLatest()) return;
      if (isAbortLikeError(error, task.signal)) {
        return;
      }
      setBackendStatus(error instanceof Error && error.message ? error.message : "流切换失败");
    } finally {
      task.finish();
    }
  }, [backendConnected, prefetchAdjacentStreams, recordStreamSwitchMetric]);

  const preparePacketStream = useCallback(async (
    packetId: number,
    preferredProtocol?: "HTTP" | "TCP" | "UDP",
    filterOverride?: string,
  ): Promise<PreparedPacketStream> => {
    const packet = await locatePacketById(packetId, filterOverride);
    if (!packet || packet.streamId == null || packet.streamId < 0) {
      return { packet, protocol: null, streamId: null };
    }

    let protocol = preferredProtocol ?? null;
    if (!protocol) {
      if (packet.proto === "HTTP") {
        protocol = "HTTP";
      } else if (packet.proto === "UDP") {
        protocol = "UDP";
      } else {
        protocol = "TCP";
      }
    }

    await setActiveStream(protocol, packet.streamId);
    return {
      packet,
      protocol,
      streamId: packet.streamId,
    };
  }, [locatePacketById, setActiveStream]);

  const persistStreamPayloads = useCallback(async (
    protocol: "HTTP" | "TCP" | "UDP",
    streamId: number,
    patches: Array<{ index: number; body: string }>,
  ) => {
    if (!backendConnected || streamId < 0 || patches.length === 0) return;
    await bridge.updateStreamPayloads(protocol, streamId, patches);

    startTransition(() => {
      if (protocol === "HTTP") {
        setHttpStream((prev) => (prev.id === streamId ? applyStreamChunkPatches(prev, patches) : prev));
        const cached = httpStreamCacheRef.current.get(streamId);
        if (cached) {
          httpStreamCacheRef.current.set(streamId, applyStreamChunkPatches(cached, patches));
        }
        return;
      }

      if (protocol === "TCP") {
        setTcpStream((prev) => (prev.id === streamId ? applyStreamChunkPatches(prev, patches) : prev));
        const cached = tcpStreamCacheRef.current.get(streamId);
        if (cached) {
          tcpStreamCacheRef.current.set(streamId, applyStreamChunkPatches(cached, patches));
        }
        return;
      }

      setUdpStream((prev) => (prev.id === streamId ? applyStreamChunkPatches(prev, patches) : prev));
      const cached = udpStreamCacheRef.current.get(streamId);
      if (cached) {
        udpStreamCacheRef.current.set(streamId, applyStreamChunkPatches(cached, patches));
      }
    });
  }, [backendConnected]);

  const scheduleLoadMoreRef = useRef(scheduleLoadMore);
  const refreshAnalysisResultRef = useRef(refreshAnalysisResult);
  const updateProgressFromStatusRef = useRef(updateProgressFromStatus);

  useEffect(() => {
    scheduleLoadMoreRef.current = scheduleLoadMore;
  }, [scheduleLoadMore]);

  useEffect(() => {
    refreshAnalysisResultRef.current = refreshAnalysisResult;
  }, [refreshAnalysisResult]);

  useEffect(() => {
    updateProgressFromStatusRef.current = updateProgressFromStatus;
  }, [updateProgressFromStatus]);

  useEffect(() => () => {
    captureTaskScopeRef.current.invalidate();
  }, []);

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
            const prefix = isOperationTimeoutError(error)
              ? "运行时组件检测超时"
              : "运行时组件检测失败";
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
          const hasActiveCapture = Boolean(activeCapturePathRef.current);
          const isProgressMessage = msg.startsWith("__progress__:");
          const isCaptureStatus = isProgressMessage
            || msg.includes("解析")
            || msg.includes("预加载")
            || msg.includes("威胁分析")
            || msg.includes("媒体流");
          if (!hasActiveCapture && isCaptureStatus) {
            return;
          }
          if (isProgressMessage) {
            updateProgressFromStatusRef.current(msg);
            wakeCaptureWaiters();
            return;
          }
          if (msg.includes("解析完成") || msg.includes("解析失败") || msg.includes("解析被取消")) {
            parseFinishedRef.current = true;
            if (msg.includes("解析失败")) {
              parseErrorRef.current = msg;
            }
          }
          if (msg.includes("媒体流分析完成") || msg.includes("媒体流分析失败")) {
            setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
          }
          if (msg.includes("威胁分析完成") || msg.includes("威胁分析失败")) {
            setThreatAnalysisProgress((prev) => prev.phase === "complete" ? prev : EMPTY_THREAT_ANALYSIS_PROGRESS);
          }
          wakeCaptureWaiters();
          setBackendStatus(msg);
        },
        error: (message) => {
          const next = message || "后端事件异常";
          const hasActiveCapture = Boolean(activeCapturePathRef.current);
          const isCaptureError = next.includes("解析")
            || next.includes("预加载")
            || next.includes("威胁分析")
            || next.includes("媒体流");
          if (!hasActiveCapture && isCaptureError) {
            return;
          }
          if (preloadingRef.current) {
            parseFinishedRef.current = true;
            parseErrorRef.current = next;
          }
          if (next.includes("媒体流")) {
            setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
          }
          if (next.includes("威胁分析")) {
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

  useEffect(() => {
    if (selectedPacketId == null) {
      setSelectedPacketDetail(null);
      return;
    }

    if (!shouldLoadSelectedPacketDetail(selectedPacketId, selectedPacketDetail)) {
      return;
    }

    const task = captureTaskScopeRef.current.beginTask("packet-detail");
    void bridge.getPacket(selectedPacketId, task.signal)
      .then((packet) => {
        if (task.isCurrent()) {
          setSelectedPacketDetail(packet);
        }
      })
      .catch((error) => {
        if (task.isCurrent() && !isAbortLikeError(error, task.signal)) {
          setSelectedPacketDetail(null);
        }
      })
      .finally(() => {
        task.finish();
      });

    return () => {
      task.abort();
    };
  }, [selectedPacketDetail?.id, selectedPacketId]);

  useEffect(() => {
    if (!shouldLoadSelectedPacketArtifacts(selectedPacketId, selectedPacket)) {
      setSelectedPacketRawHex("");
      return;
    }

    const task = captureTaskScopeRef.current.beginTask("packet-raw-hex");
    void bridge.getPacketRawHex(selectedPacket.id, task.signal)
      .then((raw) => {
        if (task.isCurrent()) {
          setSelectedPacketRawHex(raw);
        }
      })
      .catch((error) => {
        if (task.isCurrent() && !isAbortLikeError(error, task.signal)) {
          setSelectedPacketRawHex("");
        }
      })
      .finally(() => {
        task.finish();
      });

    return () => {
      task.abort();
    };
  }, [selectedPacketId, selectedPacket?.id]);

  useEffect(() => {
    if (!shouldLoadSelectedPacketArtifacts(selectedPacketId, selectedPacket)) {
      setSelectedPacketLayers(null);
      return;
    }

    const task = captureTaskScopeRef.current.beginTask("packet-layers");
    void bridge.getPacketLayers(selectedPacket.id, task.signal)
      .then((layers) => {
        if (task.isCurrent()) {
          setSelectedPacketLayers(layers);
        }
      })
      .catch((error) => {
        if (task.isCurrent() && !isAbortLikeError(error, task.signal)) {
          setSelectedPacketLayers(null);
        }
      })
      .finally(() => {
        task.finish();
      });

    return () => {
      task.abort();
    };
  }, [selectedPacketId, selectedPacket?.id]);

  const startCapture = useCallback(async (filePath?: string, filterOverride?: string) => {
    if (!backendConnected) {
      setBackendStatus("桌面后端未连接，无法打开文件");
      return;
    }

    const captureSeq = ++captureSeqRef.current;
    filterSeqRef.current += 1;
    const effectiveFilter = filterOverride ?? displayFilter;

    try {
      const opened =
        filePath && filePath.trim()
          ? { filePath: filePath.trim(), fileSize: 0, fileName: filePath.trim().split(/[\\/]/).pop() ?? "capture.pcapng" }
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
      httpStreamCacheRef.current.clear();
      tcpStreamCacheRef.current.clear();
      udpStreamCacheRef.current.clear();
      httpPrefetchInFlightRef.current.clear();
      tcpPrefetchInFlightRef.current.clear();
      udpPrefetchInFlightRef.current.clear();
      httpSwitchSeqRef.current = 0;
      tcpSwitchSeqRef.current = 0;
      udpSwitchSeqRef.current = 0;
      streamSwitchDurationsRef.current = {
        ALL: [],
        HTTP: [],
        TCP: [],
        UDP: [],
      };
      streamSwitchHitsRef.current = {
        ALL: 0,
        HTTP: 0,
        TCP: 0,
        UDP: 0,
      };
      setStreamSwitchMetrics(EMPTY_SWITCH_METRICS);
      setThreatHits([]);
      setIsThreatAnalysisLoading(false);
      setThreatAnalysisProgress(EMPTY_THREAT_ANALYSIS_PROGRESS);
      setExtractedObjects([]);
      setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
      setFileMeta({
        name: opened.fileName,
        sizeBytes: Number(opened.fileSize ?? 0),
        path: opened.filePath,
      });
      setCaptureRevision((prev) => prev + 1);
      activeCapturePathRef.current = opened.filePath;
      rememberRecentCapture({
        path: opened.filePath,
        name: opened.fileName,
        sizeBytes: Number(opened.fileSize ?? 0),
        lastOpenedAt: new Date().toISOString(),
      });

      const startTask = captureTaskScopeRef.current.beginTask("capture-start");
      try {
        await bridge.startStreamingPackets(opened.filePath, "", startTask.signal);
        if (!startTask.isCurrent()) return;
      } finally {
        startTask.finish();
      }
      if (captureSeq !== captureSeqRef.current) return;
      setBackendStatus(`正在预加载全部数据: ${opened.fileName}`);

      const waitDeadline = Date.now() + 120000;
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
        throw new Error(parseErrorRef.current || "capture parsing finished without any packets; please verify tshark compatibility");
      }
      if (!parseFinishedRef.current && Date.now() >= waitDeadline) {
        throw new Error("capture parsing timed out before preloading finished");
      }
      if (!firstPageLoaded && probePage.total > 0) {
        await loadPacketPage(0, effectiveFilter);
      }
      await refreshStreamIndex();
      if (captureSeq !== captureSeqRef.current) return;
      setBackendStatus(`预加载完成，可浏览全部流量: ${opened.fileName}`);
      void refreshAnalysisResult({
        capturePath: opened.filePath,
        quietSuccess: true,
      });
    } catch (error) {
      if (isAbortLikeError(error)) {
        return;
      }
      if (captureSeq === captureSeqRef.current) {
        setBackendStatus(error instanceof Error ? error.message : "打开文件失败");
      }
    } finally {
      if (captureSeq === captureSeqRef.current) {
        preloadingRef.current = false;
        setIsPreloadingCapture(false);
        wakeCaptureWaiters();
      }
    }
  }, [backendConnected, commitPacketPage, displayFilter, prepareForCaptureReplacement, refreshAnalysisResult, refreshStreamIndex, rememberRecentCapture, waitForCaptureSignal, wakeCaptureWaiters]);

  const applyFilter = useCallback((value?: string) => {
    const nextFilter = value ?? displayFilter;
    if (value !== undefined) {
      setDisplayFilter(nextFilter);
    }

    if (activeCapturePathRef.current && backendConnected && !isPreloadingCapture) {
      const filterSeq = ++filterSeqRef.current;
      setIsFilterLoading(true);
      resetPacketViewport();
      setBackendStatus(nextFilter.trim() ? `正在应用过滤器: ${nextFilter}` : "正在重置过滤器");
      void (async () => {
        let page = await loadPacketPage(0, nextFilter);
        const deadline = Date.now() + 10000;
        while (filterSeq === filterSeqRef.current && page?.filtering && Date.now() < deadline) {
          setBackendStatus(nextFilter.trim() ? `过滤器仍在后台扫描: ${nextFilter}` : "正在重置过滤器");
          await new Promise((resolve) => window.setTimeout(resolve, 300));
          page = await loadPacketPage(0, nextFilter);
        }
        if (filterSeq === filterSeqRef.current) {
          setIsFilterLoading(false);
          setBackendStatus(nextFilter.trim() ? `过滤器已应用: ${nextFilter}` : "过滤器已清空");
        }
      })();
    }
  }, [backendConnected, displayFilter, isPreloadingCapture, loadPacketPage, resetPacketViewport]);

  const clearFilter = useCallback(() => {
    setDisplayFilter("");

    if (activeCapturePathRef.current && backendConnected && !isPreloadingCapture) {
      const filterSeq = ++filterSeqRef.current;
      setIsFilterLoading(true);
      resetPacketViewport();
      setBackendStatus("正在重置过滤器");
      void loadPacketPage(0, "").finally(() => {
        if (filterSeq === filterSeqRef.current) {
          setIsFilterLoading(false);
          setBackendStatus("过滤器已清空");
        }
      });
    }
  }, [backendConnected, isPreloadingCapture, loadPacketPage, resetPacketViewport]);

  const selectPacket = useCallback((id: number) => {
    setSelectedPacketId(id);
    setSelectedPacketDetail((prev) => keepSelectedPacketDetailForId(prev, id));
  }, []);

  const updateDecryptionConfig = useCallback((patch: Partial<DecryptionConfig>) => {
    setDecryptionConfig((prev) => {
      const next = { ...prev, ...patch };
      if (backendConnected) {
        void bridge.updateTLSConfig(next).catch(() => setBackendStatus("TLS 配置更新失败"));
      }
      return next;
    });
  }, [backendConnected]);

  const openCapture = useCallback(async (filePath?: string) => {
    setDisplayFilter("");
    await startCapture(filePath, "");
  }, [startCapture]);

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
    setBackendStatus(backendConnected ? "当前抓包已从界面移除，正在请求后端清理线程" : "当前抓包已从界面移除；后端未连接");
    if (!backendConnected) return;

    let closeError = "";
    try {
      await bridge.cancelMediaBatchTranscription().catch(() => null);
      await bridge.closeCapture();
    } catch (error) {
      closeError = error instanceof Error ? error.message : "关闭抓包失败";
    }
    setBackendStatus(closeError ? `当前抓包已从界面移除；后端清理返回: ${closeError}` : "当前抓包已关闭，临时数据库已清理");
  }, [backendConnected, cancelAllFrontendCaptureTasks, clearCaptureUiState, wakeCaptureWaiters]);

  const protocolTree = useMemo(
    () => (selectedPacketLayers ? buildProtocolTreeFromLayers(selectedPacketLayers, selectedPacket) : buildProtocolTree(selectedPacket)),
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
