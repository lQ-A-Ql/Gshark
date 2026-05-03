import { useCallback, useEffect, useMemo, useState } from "react";
import type { GlobalTrafficStats, Packet } from "../../core/types";
import { isAbortLikeError, useAbortableRequest } from "../../hooks/useAbortableRequest";
import { bridge } from "../../integrations/wailsBridge";

export const EMPTY_TRAFFIC_STATS: GlobalTrafficStats = {
  totalPackets: 0,
  protocolKinds: 0,
  timeline: [],
  protocolDist: [],
  topTalkers: [],
  topHostnames: [],
  topDomains: [],
  topSrcIPs: [],
  topDstIPs: [],
  topComputerNames: [],
  topDestPorts: [],
  topSrcPorts: [],
};

const trafficStatsCache = new Map<string, GlobalTrafficStats>();

export interface UseTrafficGraphOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
}

export function useTrafficGraph({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
}: UseTrafficGraphOptions) {
  const captureCacheKey = useMemo(() => buildTrafficStatsCacheKey(captureRevision, filePath, totalPackets), [captureRevision, filePath, totalPackets]);
  const [stats, setStats] = useState<GlobalTrafficStats>(EMPTY_TRAFFIC_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runStatsRequest, cancel: cancelStatsRequest } = useAbortableRequest();

  const refreshStats = useCallback((force = false) => {
    if (!backendConnected) {
      cancelStatsRequest();
      setStats(EMPTY_TRAFFIC_STATS);
      setLoading(false);
      setError("");
      return;
    }

    if (!force && captureCacheKey && trafficStatsCache.has(captureCacheKey)) {
      cancelStatsRequest();
      setStats(trafficStatsCache.get(captureCacheKey) ?? EMPTY_TRAFFIC_STATS);
      setLoading(false);
      setError("");
      return;
    }

    setLoading(true);
    setError("");
    return runStatsRequest({
      request: async (signal) => {
        try {
          return await bridge.getGlobalTrafficStats(signal);
        } catch (fetchError) {
          if (isAbortLikeError(fetchError, signal)) {
            throw fetchError;
          }
          const packets = await bridge.listPackets();
          if (signal.aborted) {
            throw new DOMException("The operation was aborted.", "AbortError");
          }
          return buildStatsFromPackets(packets);
        }
      },
      onSuccess: (payload) => {
        if (captureCacheKey) {
          trafficStatsCache.set(captureCacheKey, payload);
        }
        setStats(payload);
      },
      onError: (err) => {
        setError(err instanceof Error ? err.message : "流量统计加载失败");
        setStats(EMPTY_TRAFFIC_STATS);
      },
      onSettled: () => setLoading(false),
    });
  }, [backendConnected, captureCacheKey, cancelStatsRequest, runStatsRequest]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshStats();
  }, [isPreloadingCapture, refreshStats]);

  return { stats, loading, error, refreshStats };
}

export function buildTrafficStatsCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
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
  const talkerCounts = new Map<string, number>();
  const domainCounts = new Map<string, number>();
  const srcIPCounts = new Map<string, number>();
  const dstIPCounts = new Map<string, number>();
  const computerNameCounts = new Map<string, number>();
  const dstPortCounts = new Map<string, number>();
  const srcPortCounts = new Map<string, number>();

  for (const packet of packets) {
    protocolCounts.set(packet.proto, (protocolCounts.get(packet.proto) ?? 0) + 1);
    const talker = `${packet.src} → ${packet.dst}`;
    talkerCounts.set(talker, (talkerCounts.get(talker) ?? 0) + 1);
    srcIPCounts.set(packet.src, (srcIPCounts.get(packet.src) ?? 0) + 1);
    dstIPCounts.set(packet.dst, (dstIPCounts.get(packet.dst) ?? 0) + 1);
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

  return {
    totalPackets: packets.length,
    protocolKinds: protocolCounts.size,
    timeline: [],
    protocolDist: toBuckets(protocolCounts, 20),
    topTalkers: toBuckets(talkerCounts),
    topHostnames: toBuckets(domainCounts),
    topDomains: toBuckets(domainCounts),
    topSrcIPs: toBuckets(srcIPCounts),
    topDstIPs: toBuckets(dstIPCounts),
    topComputerNames: toBuckets(computerNameCounts),
    topDestPorts: toBuckets(dstPortCounts),
    topSrcPorts: toBuckets(srcPortCounts),
  };
}
