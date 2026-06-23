import { useMemo } from "react";
import type { GlobalTrafficStats, Packet, TrafficConversation } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { buildTimelineBucketsFromPacketTimes } from "./trafficTimeline";
import type { FeaturePreloadContract } from "../../preload/preloadContracts";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";

export const EMPTY_TRAFFIC_STATS: GlobalTrafficStats = {
  totalPackets: 0,
  protocolKinds: 0,
  timeline: [],
  protocolDist: [],
  topTalkers: [],
  topConversations: [],
  topHostnames: [],
  topDomains: [],
  topSrcIPs: [],
  topDstIPs: [],
  topComputerNames: [],
  topDestPorts: [],
  topSrcPorts: [],
  protocolHierarchy: [],
};

const trafficStatsCache = createAnalysisResourceCache<GlobalTrafficStats>();

export interface UseTrafficGraphOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
}

export type TrafficStatsPreloadInput = Pick<
  UseTrafficGraphOptions,
  "backendConnected" | "filePath" | "totalPackets" | "captureRevision"
>;

export function useTrafficGraph({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
}: UseTrafficGraphOptions) {
  const cacheKey = useMemo(
    () => buildTrafficStatsCacheKey(captureRevision, filePath, totalPackets),
    [captureRevision, filePath, totalPackets],
  );
  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data: stats, loading, error, refresh: refreshStats } = useAnalysisResult<GlobalTrafficStats>({
    cache: trafficStatsCache,
    cacheKey,
    emptyValue: EMPTY_TRAFFIC_STATS,
    enabled,
    isPreloadingCapture,
    errorMessage: "流量统计加载失败",
    fetch: (signal) => backendClients.analysis.getGlobalTrafficStats(signal),
  });

  return { stats, loading, error, refreshStats };
}

export function buildTrafficStatsCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}

export const trafficStatsPreloadContract: FeaturePreloadContract<TrafficStatsPreloadInput, GlobalTrafficStats> = {
  getCacheKey(input) {
    return buildTrafficStatsCacheKey(input.captureRevision, input.filePath, input.totalPackets);
  },
  readCache(key) {
    return trafficStatsCache.get(key);
  },
  writeCache(key, data) {
    if (key) trafficStatsCache.set(key, data);
  },
  getInflight(key) {
    return trafficStatsCache.getInflight(key);
  },
  async prefetch(input, signal) {
    if (!input.backendConnected || !hasUsableCapturePath(input.filePath, input.totalPackets))
      return EMPTY_TRAFFIC_STATS;
    const key = trafficStatsPreloadContract.getCacheKey(input);
    return requestTrafficStats(key, signal, { force: false });
  },
};

export function resetTrafficStatsPreloadForTest() {
  trafficStatsCache.clear();
}

function requestTrafficStats(
  cacheKey: string,
  signal: AbortSignal,
  options: { force: boolean },
): Promise<GlobalTrafficStats> {
  return trafficStatsCache.request(cacheKey, {
    force: options.force,
    signal,
    load: () => fetchTrafficStats(signal),
  });
}

function fetchTrafficStats(signal: AbortSignal): Promise<GlobalTrafficStats> {
  return backendClients.analysis.getGlobalTrafficStats(signal);
}

function extractDomain(packet: Packet): string {
  const info = `${packet.info ?? ""}\n${packet.payload ?? ""}`;
  const patterns = [
    /(?:^|\n)Host:\s*([^\s\r\n]+)/i,
    /\bServer Name:\s*([^\s\r\n]+)/i,
    /\bSNI:\s*([^\s\r\n]+)/i,
    /\b(?:A|AAAA|CNAME|Query|Request)\s+([a-z0-9.-]+\.[a-z]{2,})\b/i,
  ];
  for (const pattern of patterns) {
    const match = info.match(pattern);
    if (match?.[1]) {
      return match[1].trim().toLowerCase();
    }
  }
  return "";
}

function extractComputerName(packet: Packet): string {
  const info = `${packet.info ?? ""}\n${packet.payload ?? ""}`;
  const patterns = [
    /\bNBNS\b.*?\b([A-Z0-9_-]{2,})(?:<[\dA-F]{2}>)?/i,
    /\bComputer Name:\s*([^\s\r\n]+)/i,
    /\bHostname:\s*([^\s\r\n]+)/i,
    /\bServer Name:\s*([^\s\r\n]+)/i,
    /\bNETBIOS(?: NAME)?\s*[:=]\s*([^\s\r\n]+)/i,
  ];
  for (const pattern of patterns) {
    const match = info.match(pattern);
    if (!match?.[1]) continue;
    const normalized = match[1].trim().replace(/<[\dA-F]{2}>$/i, "");
    if (!normalized || normalized.includes(".")) continue;
    return normalized.toUpperCase();
  }
  return "";
}

export function buildStatsFromPackets(packets: Packet[]): GlobalTrafficStats {
  const protocolCounts = new Map<string, number>();
  const endpointCounts = new Map<string, number>();
  const conversationCounts = new Map<string, number>();
  const domainCounts = new Map<string, number>();
  const srcIPCounts = new Map<string, number>();
  const dstIPCounts = new Map<string, number>();
  const computerNameCounts = new Map<string, number>();
  const dstPortCounts = new Map<string, number>();
  const srcPortCounts = new Map<string, number>();

  for (const packet of packets) {
    protocolCounts.set(packet.proto, (protocolCounts.get(packet.proto) ?? 0) + 1);
    const src = packet.src.trim();
    const dst = packet.dst.trim();

    if (src) {
      endpointCounts.set(src, (endpointCounts.get(src) ?? 0) + 1);
      srcIPCounts.set(src, (srcIPCounts.get(src) ?? 0) + 1);
    }
    if (dst) {
      endpointCounts.set(dst, (endpointCounts.get(dst) ?? 0) + 1);
      dstIPCounts.set(dst, (dstIPCounts.get(dst) ?? 0) + 1);
    }
    if (src && dst) {
      const conversationKey = `${src}\0${dst}`;
      conversationCounts.set(conversationKey, (conversationCounts.get(conversationKey) ?? 0) + 1);
    }
    if (packet.dstPort > 0) {
      dstPortCounts.set(String(packet.dstPort), (dstPortCounts.get(String(packet.dstPort)) ?? 0) + 1);
    }
    if (packet.srcPort > 0) {
      srcPortCounts.set(String(packet.srcPort), (srcPortCounts.get(String(packet.srcPort)) ?? 0) + 1);
    }
    const domain = extractDomain(packet);
    if (domain) {
      domainCounts.set(domain, (domainCounts.get(domain) ?? 0) + 1);
    }
    const computerName = extractComputerName(packet);
    if (computerName) {
      computerNameCounts.set(computerName, (computerNameCounts.get(computerName) ?? 0) + 1);
    }
  }

  const toBuckets = (counts: Map<string, number>, limit = 10) =>
    Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([label, count]) => ({ label, count }));

  const topConversations: TrafficConversation[] = Array.from(conversationCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 200)
    .map(([conversationKey, count]) => {
      const [src, dst] = conversationKey.split("\0");
      return {
        src: src ?? "",
        dst: dst ?? "",
        count,
      };
    });

  return {
    totalPackets: packets.length,
    protocolKinds: protocolCounts.size,
    timeline: buildTimelineBucketsFromPacketTimes(packets.map((packet) => packet.time)),
    protocolDist: toBuckets(protocolCounts, 20),
    topTalkers: toBuckets(endpointCounts),
    topConversations,
    topHostnames: toBuckets(domainCounts),
    topDomains: toBuckets(domainCounts),
    topSrcIPs: toBuckets(srcIPCounts),
    topDstIPs: toBuckets(dstIPCounts),
    topComputerNames: toBuckets(computerNameCounts),
    topDestPorts: toBuckets(dstPortCounts),
    topSrcPorts: toBuckets(srcPortCounts),
    protocolHierarchy: [],
  };
}
