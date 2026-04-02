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
  DEFAULT_PLUGIN_LOGS,
} from "../core/engine";
import type {
  BinaryStream,
  DecryptionConfig,
  ExtractedObject,
  HttpStream,
  Packet,
  PluginItem,
  RecentCapture,
  StreamLoadMeta,
  StreamProtocol,
  StreamSwitchMetrics,
  StreamSwitchStat,
  ThreatHit,
} from "../core/types";
import { bridge, type TSharkStatus } from "../integrations/wailsBridge";

interface PreparedPacketStream {
  packet: Packet | null;
  protocol: "HTTP" | "TCP" | "UDP" | null;
  streamId: number | null;
}

interface SentinelContextValue {
  packets: Packet[];
  totalPackets: number;
  currentPage: number;
  totalPages: number;
  isPreloadingCapture: boolean;
  preloadProcessed: number;
  preloadTotal: number;
  filteredPackets: Packet[];
  hasMorePackets: boolean;
  hasPrevPackets: boolean;
  isPageLoading: boolean;
  isFilterLoading: boolean;
  loadMorePackets: () => Promise<void>;
  loadPrevPackets: () => Promise<void>;
  jumpToPage: (page: number) => Promise<void>;
  locatePacketById: (packetId: number, filterOverride?: string) => Promise<Packet | null>;
  selectedPacket: Packet | null;
  selectedPacketRawHex: string;
  selectedPacketId: number | null;
  displayFilter: string;
  setDisplayFilter: (value: string) => void;
  applyFilter: (value?: string) => void;
  clearFilter: () => void;
  selectPacket: (id: number) => void;
  protocolTree: ReturnType<typeof buildProtocolTree>;
  hexDump: string;
  threatHits: ThreatHit[];
  extractedObjects: ExtractedObject[];
  httpStream: HttpStream;
  tcpStream: BinaryStream;
  udpStream: BinaryStream;
  streamIds: { http: number[]; tcp: number[]; udp: number[] };
  setActiveStream: (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => Promise<void>;
  persistStreamPayloads: (protocol: "HTTP" | "TCP" | "UDP", streamId: number, patches: Array<{ index: number; body: string }>) => Promise<void>;
  streamSwitchMetrics: StreamSwitchMetrics;
  plugins: PluginItem[];
  pluginLogs: string[];
  addPlugin: (plugin: PluginItem) => Promise<void>;
  deletePlugin: (id: number | string) => Promise<void>;
  togglePlugin: (id: number | string) => void;
  setPluginsEnabled: (ids: (number | string)[], enabled: boolean) => void;
  refreshPlugins: () => void;
  decryptionConfig: DecryptionConfig;
  updateDecryptionConfig: (patch: Partial<DecryptionConfig>) => void;
  fileMeta: { name: string; sizeBytes: number; path: string };
  recentCaptures: RecentCapture[];
  openCapture: (filePath?: string) => Promise<void>;
  stopCapture: () => Promise<void>;
  preparePacketStream: (packetId: number, preferredProtocol?: "HTTP" | "TCP" | "UDP", filterOverride?: string) => Promise<PreparedPacketStream>;
  backendConnected: boolean;
  backendStatus: string;
  tsharkStatus: TSharkStatus;
  isTSharkChecking: boolean;
  setTSharkPath: (path: string) => Promise<void>;
}

const SentinelContext = createContext<SentinelContextValue | null>(null);

const PAGE_SIZE = 2000;
const RAW_STREAM_PAGE_SIZE = 96;
const STREAM_PREFETCH_LIMIT = 0;
const PRELOAD_POLL_INTERVAL_MS = 120;
const PRELOAD_SIGNAL_WAIT_MS = 1000;
const TSHARK_PATH_STORAGE_KEY = "gshark.tshark-path.v1";
const RECENT_CAPTURES_STORAGE_KEY = "gshark.recent-captures.v1";
const MAX_RECENT_CAPTURES = 8;
const EMPTY_TSHARK_STATUS: TSharkStatus = {
  available: false,
  path: "",
  message: "",
  customPath: "",
  usingCustomPath: false,
};

const EMPTY_HTTP_STREAM: HttpStream = {
  id: -1,
  client: "",
  server: "",
  request: "",
  response: "",
  chunks: [],
};

const EMPTY_BINARY_STREAM: BinaryStream = {
  id: -1,
  protocol: "TCP",
  from: "",
  to: "",
  chunks: [],
  nextCursor: 0,
  totalChunks: 0,
  hasMore: false,
};

const EMPTY_SWITCH_STAT: StreamSwitchStat = {
  count: 0,
  lastMs: 0,
  p50Ms: 0,
  p95Ms: 0,
  cacheHitRate: 0,
};

const EMPTY_SWITCH_METRICS: StreamSwitchMetrics = {
  overall: { ...EMPTY_SWITCH_STAT },
  byProtocol: {
    HTTP: { ...EMPTY_SWITCH_STAT },
    TCP: { ...EMPTY_SWITCH_STAT },
    UDP: { ...EMPTY_SWITCH_STAT },
  },
};

const SWITCH_SAMPLE_LIMIT = 300;

function calcPercentile(values: number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil((percentile / 100) * sorted.length) - 1));
  return Number(sorted[idx].toFixed(1));
}

function buildSwitchStat(values: number[], hitCount: number): StreamSwitchStat {
  const count = values.length;
  if (count === 0) return { ...EMPTY_SWITCH_STAT };
  const lastMs = Number(values[count - 1].toFixed(1));
  const p50Ms = calcPercentile(values, 50);
  const p95Ms = calcPercentile(values, 95);
  const cacheHitRate = Number(((hitCount / count) * 100).toFixed(1));
  return { count, lastMs, p50Ms, p95Ms, cacheHitRate };
}

function isFastPathLoad(meta?: StreamLoadMeta): boolean {
  if (!meta) return false;
  return Boolean(meta.cacheHit || meta.indexHit || meta.source === "memory" || meta.source === "cache");
}

function markCachedLoad<T extends HttpStream | BinaryStream>(stream: T): T {
  return {
    ...stream,
    loadMeta: {
      ...(stream.loadMeta ?? {}),
      source: "cache",
      cacheHit: true,
    },
  };
}

function buildLoadingHttpStream(streamId: number): HttpStream {
  return {
    id: streamId,
    client: "",
    server: "",
    request: "",
    response: "",
    chunks: [],
    loadMeta: {
      source: "loading",
      loading: true,
    },
  };
}

function buildLoadingBinaryStream(protocol: "TCP" | "UDP", streamId: number): BinaryStream {
  return {
    id: streamId,
    protocol,
    from: "",
    to: "",
    chunks: [],
    nextCursor: 0,
    totalChunks: 0,
    hasMore: false,
    loadMeta: {
      source: "loading",
      loading: true,
    },
  };
}

function prettySize(bytes: number) {
  const mb = bytes / 1024 / 1024;
  return `${mb.toFixed(1)} MB`;
}

function readRecentCaptures(): RecentCapture[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RECENT_CAPTURES_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((item) => ({
        path: String(item?.path ?? "").trim(),
        name: String(item?.name ?? "").trim(),
        sizeBytes: Number(item?.sizeBytes ?? 0),
        lastOpenedAt: String(item?.lastOpenedAt ?? "").trim(),
      }))
      .filter((item) => item.path)
      .slice(0, MAX_RECENT_CAPTURES);
  } catch {
    return [];
  }
}

function writeRecentCaptures(items: RecentCapture[]) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(RECENT_CAPTURES_STORAGE_KEY, JSON.stringify(items.slice(0, MAX_RECENT_CAPTURES)));
  } catch {
    // ignore persistence failures
  }
}

function applyStreamChunkPatches<T extends HttpStream | BinaryStream>(
  stream: T,
  patches: Array<{ index: number; body: string }>,
): T {
  if (patches.length === 0 || stream.chunks.length === 0) return stream;

  const patchMap = new Map<number, string>();
  for (const patch of patches) {
    if (patch.index < 0) continue;
    patchMap.set(patch.index, patch.body);
  }
  if (patchMap.size === 0) return stream;

  const nextChunks = stream.chunks.map((chunk, index) => (
    patchMap.has(index) ? { ...chunk, body: patchMap.get(index) ?? chunk.body } : chunk
  ));

  if ("request" in stream && "response" in stream) {
    return {
      ...stream,
      chunks: nextChunks,
      request: nextChunks.filter((chunk) => chunk.direction === "client").map((chunk) => chunk.body).join(""),
      response: nextChunks.filter((chunk) => chunk.direction === "server").map((chunk) => chunk.body).join(""),
    };
  }

  return {
    ...stream,
    chunks: nextChunks,
  };
}

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
  const [selectedPacketRawHex, setSelectedPacketRawHex] = useState("");
  const [selectedPacketLayers, setSelectedPacketLayers] = useState<Record<string, unknown> | null>(null);
  const [plugins, setPlugins] = useState<PluginItem[]>([]);
  const [pluginLogs, setPluginLogs] = useState<string[]>(DEFAULT_PLUGIN_LOGS);
  const [backendConnected, setBackendConnected] = useState(false);
  const [backendStatus, setBackendStatus] = useState("等待后端连接");
  const [tsharkStatus, setTsharkStatus] = useState<TSharkStatus>(EMPTY_TSHARK_STATUS);
  const [isTSharkChecking, setIsTSharkChecking] = useState(false);
  const [threatHits, setThreatHits] = useState<ThreatHit[]>([]);
  const [extractedObjects, setExtractedObjects] = useState<ExtractedObject[]>([]);
  const [httpStream, setHttpStream] = useState<HttpStream>(EMPTY_HTTP_STREAM);
  const [tcpStream, setTcpStream] = useState<BinaryStream>(EMPTY_BINARY_STREAM);
  const [udpStream, setUdpStream] = useState<BinaryStream>({ ...EMPTY_BINARY_STREAM, protocol: "UDP" });
  const [streamIds, setStreamIds] = useState<{ http: number[]; tcp: number[]; udp: number[] }>({
    http: [],
    tcp: [],
    udp: [],
  });
  const [fileMeta, setFileMeta] = useState({
    name: "未打开文件",
    sizeBytes: 0,
    path: "",
  });
  const [recentCaptures, setRecentCaptures] = useState<RecentCapture[]>(() => readRecentCaptures());
  const [decryptionConfig, setDecryptionConfig] = useState<DecryptionConfig>({
    sslKeyLogPath: "",
    privateKeyPath: "",
    privateKeyIpPort: "",
  });

  const refreshTimer = useRef<number | null>(null);
  const pageStartRef = useRef(0);
  const packetPageSeqRef = useRef(0);
  const packetPageAbortRef = useRef<AbortController | null>(null);
  const hasMorePacketsRef = useRef(false);
  const loadMoreScheduledRef = useRef<number | null>(null);
  const backendRetryTimerRef = useRef<number | null>(null);
  const parseFinishedRef = useRef(false);
  const parseErrorRef = useRef("");
  const preloadingRef = useRef(false);
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
  const httpRequestAbortRef = useRef<AbortController | null>(null);
  const tcpRequestAbortRef = useRef<AbortController | null>(null);
  const udpRequestAbortRef = useRef<AbortController | null>(null);
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

  const cancelPacketPageLoad = useCallback(() => {
    packetPageSeqRef.current += 1;
    packetPageAbortRef.current?.abort();
    packetPageAbortRef.current = null;
    setIsPageLoading(false);
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
    setSelectedPacketRawHex("");
    setSelectedPacketLayers(null);
  }, [cancelPacketPageLoad]);

  const loadPacketPage = useCallback(async (
    cursor: number,
    filterOverride?: string,
    options?: { finishFilterLoading?: boolean },
  ) => {
    if (!backendConnected) return null;
    const requestSeq = ++packetPageSeqRef.current;
    packetPageAbortRef.current?.abort();
    const abortController = new AbortController();
    packetPageAbortRef.current = abortController;
    setIsPageLoading(true);
    try {
      const safeCursor = Math.max(0, cursor);
      const page = await bridge.listPacketsPage(safeCursor, PAGE_SIZE, filterOverride ?? displayFilter, abortController.signal);
      if (abortController.signal.aborted || requestSeq !== packetPageSeqRef.current) {
        return null;
      }
      pageStartRef.current = safeCursor;
      setPageStart(safeCursor);
      setTotalPackets(page.total);
      setPackets(page.items);
      setSelectedPacketId((prev) => {
        if (prev == null) return null;
        return page.items.some((p) => p.id === prev) ? prev : null;
      });
      setSelectedPacketRawHex("");
      setSelectedPacketLayers(null);
      setHasPrevPackets(safeCursor > 0);
      hasMorePacketsRef.current = page.hasMore;
      setHasMorePackets(page.hasMore);
      return page;
    } catch (error) {
      if (abortController.signal.aborted) {
        return null;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        return null;
      }
      if (error instanceof Error && error.name === "AbortError") {
        return null;
      }
      setBackendStatus(error instanceof Error ? error.message : "数据包加载失败");
      return null;
    } finally {
      if (packetPageAbortRef.current === abortController) {
        packetPageAbortRef.current = null;
      }
      if (requestSeq === packetPageSeqRef.current) {
        setIsPageLoading(false);
        if (options?.finishFilterLoading) {
          setIsFilterLoading(false);
        }
      }
    }
  }, [backendConnected, displayFilter]);

  const loadMorePackets = useCallback(async () => {
    const next = pageStartRef.current + PAGE_SIZE;
    await loadPacketPage(next);
  }, [loadPacketPage]);

  const loadPrevPackets = useCallback(async () => {
    const prev = Math.max(0, pageStartRef.current - PAGE_SIZE);
    await loadPacketPage(prev);
  }, [loadPacketPage]);

  const jumpToPage = useCallback(async (page: number) => {
    const totalPagesHint = Math.max(1, Math.ceil(totalPackets / PAGE_SIZE));
    const targetPage = Math.max(1, Math.min(Number.isFinite(page) ? Math.floor(page) : 1, totalPagesHint));
    const cursor = (targetPage - 1) * PAGE_SIZE;
    await loadPacketPage(cursor);
  }, [loadPacketPage, totalPackets]);

  const locatePacketById = useCallback(async (packetId: number, filterOverride?: string) => {
    const normalized = Number.isFinite(packetId) ? Math.floor(packetId) : 0;
    if (normalized <= 0) return null;
    try {
      const effectiveFilter = filterOverride ?? displayFilter;
      const located = await bridge.locatePacketPage(normalized, PAGE_SIZE, effectiveFilter);
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
      setSelectedPacketId(normalized);
      return page.items.find((item) => item.id === normalized) ?? null;
    } catch (error) {
      setBackendStatus(error instanceof Error ? error.message : "定位数据包失败");
      return null;
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
    if (!message.startsWith("__progress__:")) return false;
    const parts = message.split(":");
    if (parts.length < 4) return true;
    const phase = parts[1];
    const processed = Number(parts[2]) || 0;
    const total = Number(parts[3]) || 0;
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
    if (captureWaitersRef.current.size === 0) return;
    const waiters = Array.from(captureWaitersRef.current);
    captureWaitersRef.current.clear();
    for (const waiter of waiters) {
      waiter();
    }
  }, []);

  const waitForCaptureSignal = useCallback((delayMs: number) => (
    new Promise<void>((resolve) => {
      let settled = false;
      let timer = 0;
      const finish = () => {
        if (settled) return;
        settled = true;
        if (timer) {
          window.clearTimeout(timer);
        }
        captureWaitersRef.current.delete(finish);
        resolve();
      };
      timer = window.setTimeout(finish, delayMs);
      captureWaitersRef.current.add(finish);
    })
  ), []);

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
    const nextPath = path.trim();
    if (!backendConnected) {
      if (typeof window !== "undefined") {
        if (nextPath) {
          window.localStorage.setItem(TSHARK_PATH_STORAGE_KEY, nextPath);
        } else {
          window.localStorage.removeItem(TSHARK_PATH_STORAGE_KEY);
        }
      }
      setTsharkStatus((prev) => ({
        ...prev,
        customPath: nextPath,
        usingCustomPath: nextPath.length > 0,
      }));
      return;
    }

    const status = await bridge.setTSharkPath(nextPath);
    setTsharkStatus(status);

    if (typeof window !== "undefined") {
      if (nextPath) {
        window.localStorage.setItem(TSHARK_PATH_STORAGE_KEY, nextPath);
      } else {
        window.localStorage.removeItem(TSHARK_PATH_STORAGE_KEY);
      }
    }

    if (status.available) {
      if (status.message && status.message !== "ok") {
        setBackendStatus(status.message);
      } else {
        setBackendStatus(status.usingCustomPath ? `tshark ready: ${status.path}` : "tshark ready");
      }
      return;
    }
    setBackendStatus(status.message || "tshark is unavailable");
    throw new Error(status.message || "tshark is unavailable");
  }, [backendConnected]);

  const filteredPackets = useMemo(() => packets, [packets]);

  const selectedPacket = useMemo(() => {
    if (selectedPacketId == null) return filteredPackets[0] ?? null;
    return filteredPackets.find((p) => p.id === selectedPacketId) ?? null;
  }, [filteredPackets, selectedPacketId]);

  const refreshAnalysisResult = useCallback(async () => {
    if (!backendConnected) return;
    try {
      const [hits, objects] = await Promise.all([
        bridge.listThreatHits(["flag{", "ctf{"]),
        bridge.listObjects(),
      ]);
      setThreatHits(hits);
      setExtractedObjects(objects);
    } catch {
      setBackendStatus("分析结果刷新失败");
    }
  }, [backendConnected]);

  const refreshStreamIndex = useCallback(async () => {
    if (!backendConnected) return;
    try {
      const [httpIds, tcpIds, udpIds] = await Promise.all([
        bridge.listStreamIds("HTTP"),
        bridge.listStreamIds("TCP"),
        bridge.listStreamIds("UDP"),
      ]);
      setStreamIds({ http: httpIds, tcp: tcpIds, udp: udpIds });
    } catch {
      setBackendStatus("流索引刷新失败");
    }
  }, [backendConnected]);

  const prefetchAdjacentStreams = useCallback((protocol: "HTTP" | "TCP" | "UDP", currentStreamId: number) => {
    if (!backendConnected || currentStreamId < 0 || STREAM_PREFETCH_LIMIT <= 0) return;

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
        httpPrefetchInFlightRef.current.add(targetId);
        void bridge
          .getHttpStream(targetId)
          .then((http) => {
            httpStreamCacheRef.current.set(http.id, http);
          })
          .finally(() => {
            httpPrefetchInFlightRef.current.delete(targetId);
          });
        continue;
      }

      if (protocol === "TCP") {
        if (tcpStreamCacheRef.current.has(targetId) || tcpPrefetchInFlightRef.current.has(targetId)) continue;
        if (tcpPrefetchInFlightRef.current.size >= 2) continue;
        tcpPrefetchInFlightRef.current.add(targetId);
        void bridge
          .getRawStreamPage("TCP", targetId, 0, RAW_STREAM_PAGE_SIZE)
          .then((raw) => {
            tcpStreamCacheRef.current.set(raw.id, raw);
          })
          .finally(() => {
            tcpPrefetchInFlightRef.current.delete(targetId);
          });
        continue;
      }

      if (udpStreamCacheRef.current.has(targetId) || udpPrefetchInFlightRef.current.has(targetId)) continue;
      if (udpPrefetchInFlightRef.current.size >= 2) continue;
      udpPrefetchInFlightRef.current.add(targetId);
      void bridge
        .getRawStreamPage("UDP", targetId, 0, RAW_STREAM_PAGE_SIZE)
        .then((raw) => {
          udpStreamCacheRef.current.set(raw.id, raw);
        })
        .finally(() => {
          udpPrefetchInFlightRef.current.delete(targetId);
        });
    }
  }, [backendConnected, streamIds.http, streamIds.tcp, streamIds.udp]);

  const setActiveStream = useCallback(async (protocol: "HTTP" | "TCP" | "UDP", streamId: number) => {
    if (!backendConnected || streamId < 0) return;
    const startedAt = typeof performance !== "undefined" ? performance.now() : Date.now();
    let cacheHit = false;

    const requestAbortRef =
      protocol === "HTTP"
        ? httpRequestAbortRef
        : protocol === "TCP"
          ? tcpRequestAbortRef
          : udpRequestAbortRef;
    requestAbortRef.current?.abort();
    const abortController = new AbortController();
    requestAbortRef.current = abortController;

    const requestSeq = protocol === "HTTP"
      ? ++httpSwitchSeqRef.current
      : protocol === "TCP"
        ? ++tcpSwitchSeqRef.current
        : ++udpSwitchSeqRef.current;

    const isLatest = () => {
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
        const http = await bridge.getHttpStream(streamId, abortController.signal);
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
      const raw = await bridge.getRawStreamPage(protocol, streamId, 0, RAW_STREAM_PAGE_SIZE, abortController.signal);
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
      if (error instanceof DOMException && error.name === "AbortError") {
        return;
      }
      if (error instanceof Error && error.name === "AbortError") {
        return;
      }
      setBackendStatus(error instanceof Error && error.message ? error.message : "流切换失败");
    } finally {
      if (requestAbortRef.current === abortController) {
        requestAbortRef.current = null;
      }
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
    cancelPacketPageLoad();
  }, [cancelPacketPageLoad]);

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
        setBackendStatus("后端未连接，请先启动 backend 服务");
        scheduleBackendRetry();
        return;
      }

      clearBackendRetryTimer();
      setBackendConnected(true);
      setBackendStatus("后端已连接，等待打开文件");
      setIsTSharkChecking(true);

      try {
        const savedTSharkPath =
          typeof window !== "undefined" ? window.localStorage.getItem(TSHARK_PATH_STORAGE_KEY)?.trim() ?? "" : "";
        const tshark = await bridge.setTSharkPath(savedTSharkPath);
        setTsharkStatus(tshark);
        if (!cancelled && tshark.available && tshark.message && tshark.message !== "ok") {
          setBackendStatus(tshark.message);
        }
        if (!cancelled && !tshark.available) {
          setBackendStatus(tshark.message || "未检测到 tshark，请先配置路径");
        }
      } catch {
        // Ignore tool-check errors to avoid blocking app startup.
      } finally {
        if (!cancelled) {
          setIsTSharkChecking(false);
        }
      }

      try {
        const [backendPlugins, tls] = await Promise.all([
          bridge.listPlugins(),
          bridge.getTLSConfig(),
        ]);

        setPlugins(backendPlugins);
        if (tls) {
          setDecryptionConfig(tls);
        }
      } catch {
        setBackendStatus("后端初始化失败");
      }

      dispose = bridge.subscribeEvents({
        packet: (packet) => {
          setSelectedPacketId((prev) => prev ?? packet.id);
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
          if (updateProgressFromStatusRef.current(msg)) {
            wakeCaptureWaiters();
            return;
          }
          if (msg.toLowerCase().includes("plugin")) {
            setPluginLogs((logs) => [
              `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] [DEBUG] ${msg}`,
              ...logs,
            ].slice(0, 120));
          }
          if (msg.includes("解析完成") || msg.includes("解析失败") || msg.includes("解析被取消")) {
            parseFinishedRef.current = true;
            if (msg.includes("解析失败")) {
              parseErrorRef.current = msg;
            }
          }
          wakeCaptureWaiters();
          setBackendStatus(msg);
        },
        error: (message) => {
          const next = message || "后端事件异常";
          if (preloadingRef.current) {
            parseFinishedRef.current = true;
            parseErrorRef.current = next;
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
    if (selectedPacketId == null || !selectedPacket) {
      setSelectedPacketRawHex("");
      return;
    }

    let cancelled = false;
    void bridge.getPacketRawHex(selectedPacket.id)
      .then((raw) => {
        if (!cancelled) {
          setSelectedPacketRawHex(raw);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedPacketRawHex("");
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedPacketId, selectedPacket?.id]);

  useEffect(() => {
    if (selectedPacketId == null || !selectedPacket) {
      setSelectedPacketLayers(null);
      return;
    }

    let cancelled = false;
    void bridge.getPacketLayers(selectedPacket.id)
      .then((layers) => {
        if (!cancelled) {
          setSelectedPacketLayers(layers);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSelectedPacketLayers(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedPacketId, selectedPacket?.id]);

  const startCapture = useCallback(async (filePath?: string, filterOverride?: string) => {
    if (!backendConnected) {
      setBackendStatus("后端未连接，无法打开文件");
      return;
    }

    const effectiveFilter = filterOverride ?? displayFilter;

    try {
      const opened =
        filePath && filePath.trim()
          ? { filePath: filePath.trim(), fileSize: 0, fileName: filePath.trim().split(/[\\/]/).pop() ?? "capture.pcapng" }
          : await bridge.openPcapFile();

      setIsFilterLoading(false);
      cancelPacketPageLoad();
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
      setExtractedObjects([]);
      setFileMeta({
        name: opened.fileName,
        sizeBytes: Number(opened.fileSize ?? 0),
        path: opened.filePath,
      });
      activeCapturePathRef.current = opened.filePath;
      rememberRecentCapture({
        path: opened.filePath,
        name: opened.fileName,
        sizeBytes: Number(opened.fileSize ?? 0),
        lastOpenedAt: new Date().toISOString(),
      });

      await bridge.startStreamingPackets(opened.filePath, "");
      setBackendStatus(`正在预加载全部数据: ${opened.fileName}`);

      const waitDeadline = Date.now() + 120000;
      let firstPageLoaded = false;
      while (Date.now() < waitDeadline) {
        if (!firstPageLoaded) {
          const firstPage = await bridge.listPacketsPage(0, 1, effectiveFilter);
          if (firstPage.total > 0) {
            await loadPacketPage(0, effectiveFilter);
            firstPageLoaded = true;
          }
        }

        if (parseFinishedRef.current) {
          break;
        }

        await waitForCaptureSignal(firstPageLoaded ? PRELOAD_SIGNAL_WAIT_MS : PRELOAD_POLL_INTERVAL_MS);
      }

      const probePage = await bridge.listPacketsPage(0, 1, effectiveFilter);
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
      await refreshAnalysisResult();
      setBackendStatus(`预加载完成，可浏览全部流量: ${opened.fileName}`);
    } catch (error) {
      setBackendStatus(error instanceof Error ? error.message : "打开文件失败");
    } finally {
      preloadingRef.current = false;
      setIsPreloadingCapture(false);
      wakeCaptureWaiters();
    }
  }, [backendConnected, cancelPacketPageLoad, displayFilter, loadPacketPage, refreshAnalysisResult, refreshStreamIndex, rememberRecentCapture, waitForCaptureSignal, wakeCaptureWaiters]);

  const applyFilter = useCallback((value?: string) => {
    const nextFilter = value ?? displayFilter;
    if (value !== undefined) {
      setDisplayFilter(nextFilter);
    }

    if (activeCapturePathRef.current && backendConnected && !isPreloadingCapture) {
      setIsFilterLoading(true);
      resetPacketViewport();
      setBackendStatus(nextFilter.trim() ? `正在应用过滤器: ${nextFilter}` : "正在重置过滤器");
      void loadPacketPage(0, nextFilter, { finishFilterLoading: true });
    }
  }, [backendConnected, displayFilter, isPreloadingCapture, loadPacketPage, resetPacketViewport]);

  const clearFilter = useCallback(() => {
    setDisplayFilter("");

    if (activeCapturePathRef.current && backendConnected && !isPreloadingCapture) {
      setIsFilterLoading(true);
      resetPacketViewport();
      setBackendStatus("正在重置过滤器");
      void loadPacketPage(0, "", { finishFilterLoading: true });
    }
  }, [backendConnected, isPreloadingCapture, loadPacketPage, resetPacketViewport]);

  const selectPacket = useCallback((id: number) => {
    setSelectedPacketId(id);
  }, []);

  const togglePlugin = useCallback((id: number | string) => {
    if (!backendConnected) {
      setBackendStatus("后端未连接，无法切换插件");
      return;
    }

    void bridge
      .togglePlugin(String(id))
      .then((updated) => {
        setPlugins((prev) => prev.map((plugin) => (String(plugin.id) === String(updated.id) ? updated : plugin)));
        setPluginLogs((logs) => [
          `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] [INFO] ${updated.name} ${updated.enabled ? "已启用" : "已禁用"}`,
          ...logs,
        ].slice(0, 120));
      })
      .catch(() => setBackendStatus("插件切换失败"));
  }, [backendConnected]);

  const addPlugin = useCallback(async (plugin: PluginItem) => {
    if (!backendConnected) {
      setBackendStatus("后端未连接，无法新增插件");
      return;
    }
    try {
      const added = await bridge.addPlugin(plugin);
      setPlugins((prev) => {
        const existingIndex = prev.findIndex((p) => String(p.id) === String(added.id));
        if (existingIndex >= 0) {
          const next = [...prev];
          next[existingIndex] = added;
          return next;
        }
        return [added, ...prev];
      });
      setPluginLogs((logs) => [
        `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] [INFO] 已新增插件 ${added.name} (${added.id})`,
        ...logs,
      ].slice(0, 120));
    } catch (error) {
      const message = error instanceof Error ? error.message : "新增插件失败";
      setBackendStatus(message);
      setPluginLogs((logs) => [
        `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] [WARN] 新增插件失败: ${message}`,
        ...logs,
      ].slice(0, 120));
      throw error instanceof Error ? error : new Error(message);
    }
  }, [backendConnected]);

  const deletePlugin = useCallback(async (id: number | string) => {
    if (!backendConnected) {
      setBackendStatus("后端未连接，无法删除插件");
      return;
    }
    try {
      await bridge.deletePlugin(String(id));
      setPlugins((prev) => prev.filter((p) => String(p.id) !== String(id)));
      setPluginLogs((logs) => [
        `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] [INFO] 已删除插件 ${id}`,
        ...logs,
      ].slice(0, 120));
    } catch {
      setBackendStatus("删除插件失败");
    }
  }, [backendConnected]);

  const setPluginsEnabled = useCallback((ids: (number | string)[], enabled: boolean) => {
    if (!backendConnected) {
      setBackendStatus("后端未连接，无法批量设置插件");
      return;
    }

    void bridge
      .setPluginsEnabled(ids.map((id) => String(id)), enabled)
      .then((updated) => {
        if (ids.length === 0) {
          setPlugins(updated);
        } else {
          const map = new Map(updated.map((p) => [String(p.id), p]));
          setPlugins((prev) => prev.map((p) => map.get(String(p.id)) ?? p));
        }

        const scope = ids.length === 0 ? "全部插件" : `${ids.length} 个插件`;
        setPluginLogs((logs) => [
          `[${new Date().toLocaleTimeString("zh-CN", { hour12: false })}] [INFO] ${scope}${enabled ? "已启用" : "已禁用"}`,
          ...logs,
        ].slice(0, 120));
      })
      .catch(() => setBackendStatus("批量插件设置失败"));
  }, [backendConnected]);

  const refreshPlugins = useCallback(() => {
    if (!backendConnected) return;
    void bridge
      .listPlugins()
      .then((items) => {
        setPlugins(items);
      })
      .catch(() => setBackendStatus("插件列表刷新失败"));
  }, [backendConnected]);

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
    if (!backendConnected) return;
    setIsFilterLoading(false);
    await bridge.stopStreamingPackets();
    setBackendStatus("解析已停止");
  }, [backendConnected]);

  const protocolTree = useMemo(
    () => (selectedPacketLayers ? buildProtocolTreeFromLayers(selectedPacketLayers, selectedPacket) : buildProtocolTree(selectedPacket)),
    [selectedPacketLayers, selectedPacket],
  );
  const hexDump = useMemo(() => buildHexDump(selectedPacket), [selectedPacket]);
  const currentPage = useMemo(() => Math.floor(pageStart / PAGE_SIZE) + 1, [pageStart]);
  const totalPages = useMemo(() => Math.max(1, Math.ceil(totalPackets / PAGE_SIZE)), [totalPackets]);

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
      extractedObjects,
      httpStream,
      tcpStream,
      udpStream,
      streamIds,
      setActiveStream,
      persistStreamPayloads,
      streamSwitchMetrics,
      plugins,
      pluginLogs,
      addPlugin,
      deletePlugin,
      togglePlugin,
      setPluginsEnabled,
      refreshPlugins,
      decryptionConfig,
      updateDecryptionConfig,
      fileMeta,
      recentCaptures,
      openCapture,
      stopCapture,
      preparePacketStream,
      backendConnected,
      backendStatus,
      tsharkStatus,
      isTSharkChecking,
      setTSharkPath,
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
      extractedObjects,
      httpStream,
      tcpStream,
      udpStream,
      streamIds,
      setActiveStream,
      persistStreamPayloads,
      streamSwitchMetrics,
      plugins,
      pluginLogs,
      addPlugin,
      deletePlugin,
      togglePlugin,
      setPluginsEnabled,
      refreshPlugins,
      decryptionConfig,
      updateDecryptionConfig,
      fileMeta,
      recentCaptures,
      openCapture,
      stopCapture,
      preparePacketStream,
      backendConnected,
      backendStatus,
      tsharkStatus,
      isTSharkChecking,
      setTSharkPath,
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
