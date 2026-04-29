import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, BarChart3, Clock3 } from "lucide-react";
import { useNavigate } from "react-router";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { AnalysisEmptyState, AnalysisPanel, AnalysisStatCard } from "../components/analysis/AnalysisPrimitives";
import { bridge } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";
import type { Packet, GlobalTrafficStats } from "../core/types";

interface Bucket {
  label: string;
  count: number;
}

const EMPTY_STATS: GlobalTrafficStats = {
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

export default function TrafficGraph() {
  const navigate = useNavigate();
  const { totalPackets, backendConnected, isPreloadingCapture, fileMeta, setDisplayFilter, applyFilter, captureRevision } = useSentinel();
  const captureCacheKey = useMemo(() => {
    return buildTrafficStatsCacheKey(captureRevision, fileMeta.path, totalPackets);
  }, [captureRevision, fileMeta.path, totalPackets]);
  const [stats, setStats] = useState<GlobalTrafficStats>(EMPTY_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const requestAbortRef = useRef<AbortController | null>(null);
  const requestSeqRef = useRef(0);

  const refreshStats = useCallback((force = false) => {
    if (!backendConnected) {
      setStats(EMPTY_STATS);
      setLoading(false);
      setError("");
      return;
    }

    if (!force && captureCacheKey && trafficStatsCache.has(captureCacheKey)) {
      setStats(trafficStatsCache.get(captureCacheKey) ?? EMPTY_STATS);
      setLoading(false);
      setError("");
      return;
    }

    setLoading(true);
    setError("");
    requestAbortRef.current?.abort();
    const abortController = new AbortController();
    requestAbortRef.current = abortController;
    const requestSeq = ++requestSeqRef.current;
    const isLatest = () => requestSeq === requestSeqRef.current;
    void bridge
      .getGlobalTrafficStats(abortController.signal)
      .then((payload) => {
        if (!isLatest()) return;
        if (captureCacheKey) {
          trafficStatsCache.set(captureCacheKey, payload);
        }
        setStats(payload);
      })
      .catch(async (e) => {
        if (!isLatest() || abortController.signal.aborted) return;
        // Backward compatibility for old backend without global stats endpoint.
        try {
          const packets = await bridge.listPackets();
          if (!isLatest()) return;
          const fallback = buildStatsFromPackets(packets);
          if (captureCacheKey) {
            trafficStatsCache.set(captureCacheKey, fallback);
          }
          setStats(fallback);
          setError("");
          return;
        } catch {
          const msg = e instanceof Error ? e.message : "全局流量统计加载失败";
          setError(msg);
          setStats(EMPTY_STATS);
        }
      })
      .finally(() => {
        if (requestAbortRef.current === abortController) {
          requestAbortRef.current = null;
        }
        if (isLatest()) {
          setLoading(false);
        }
      });
    return () => {
      abortController.abort();
      if (requestAbortRef.current === abortController) {
        requestAbortRef.current = null;
      }
    };
  }, [backendConnected, captureCacheKey]);

  useEffect(() => () => {
    requestAbortRef.current?.abort();
  }, []);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshStats();
  }, [refreshStats, isPreloadingCapture]);

  const timeline = useMemo(() => stats.timeline, [stats.timeline]);
  const protocolDist = useMemo(() => stats.protocolDist, [stats.protocolDist]);
  const topSrcIPs = useMemo(() => stats.topSrcIPs || [], [stats.topSrcIPs]);
  const topDstIPs = useMemo(() => stats.topDstIPs || [], [stats.topDstIPs]);
  const topComputerNames = useMemo(() => stats.topComputerNames || [], [stats.topComputerNames]);
  const topDomains = useMemo(() => stats.topDomains || stats.topHostnames || [], [stats.topDomains, stats.topHostnames]);
  const topDestPorts = useMemo(() => stats.topDestPorts || [], [stats.topDestPorts]);
  const topSrcPorts = useMemo(() => stats.topSrcPorts || [], [stats.topSrcPorts]);

  const jumpWithFilter = useCallback((filter: string) => {
    if (!filter.trim()) return;
    setDisplayFilter(filter);
    applyFilter(filter);
    navigate("/");
  }, [applyFilter, navigate, setDisplayFilter]);

  return (
    <PageShell className="bg-[radial-gradient(circle_at_top,rgba(251,191,36,0.28),transparent_36%),linear-gradient(180deg,#fffaf0_0%,#fbfbff_44%,#f8fafc_100%)]">
      <AnalysisHero
        icon={<BarChart3 className="h-5 w-5" />}
        title="流量图分析"
        subtitle="GLOBAL TRAFFIC OVERVIEW"
        description="统一查看全局协议分布、时序趋势、热点 IP、端口与域名，适合作为进入其他专题分析前的总览视角。"
        tags={["全局视图", "忽略过滤器", "协议分布", "会话热点"]}
        tagsLabel="视图层"
        theme="amber"
        onRefresh={() => refreshStats(true)}
      />

      {loading && (
        <div className="mb-3 rounded-2xl border border-amber-100 bg-white/88 px-4 py-3 text-xs font-medium text-slate-500 shadow-[0_18px_48px_rgba(148,163,184,0.14)] backdrop-blur-xl">正在加载全局流量统计...</div>
      )}

      {!loading && error && (
        <div className="mb-3 flex items-center justify-between rounded-2xl border border-amber-200 bg-amber-50/88 px-4 py-3 text-xs text-amber-700 shadow-[0_18px_48px_rgba(245,158,11,0.12)] backdrop-blur-xl">
          <span>{error}</span>
          <button className="rounded-full border border-amber-200 bg-white/90 px-3 py-1 font-semibold shadow-sm transition-all hover:bg-amber-100" onClick={() => refreshStats(true)}>重试</button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <AnalysisStatCard title="总包数" value={stats.totalPackets.toLocaleString()} icon={<Activity className="h-4 w-4 text-emerald-600" />} tone="amber" />
        <AnalysisStatCard title="协议种类" value={String(stats.protocolKinds)} icon={<BarChart3 className="h-4 w-4 text-indigo-600" />} tone="amber" />
        <AnalysisStatCard title="时间窗口" value={timeline.length > 0 ? `${timeline[0].label} ~ ${timeline[timeline.length - 1].label}` : "--"} icon={<Clock3 className="h-4 w-4 text-amber-600" />} tone="amber" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <AnalysisPanel title="每秒流量趋势" tone="amber">
          <SimpleBarChart data={timeline} color="bg-blue-500" />
        </AnalysisPanel>
        <AnalysisPanel title="协议分布" tone="amber">
          <SimpleBarChart data={protocolDist} color="bg-emerald-500" onSelect={(row) => jumpWithFilter(filterForProtocolBucket(row.label))} />
        </AnalysisPanel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <AnalysisPanel title="源 IP" tone="amber">
          <SimpleBarChart data={topSrcIPs} color="bg-violet-500" onSelect={(row) => jumpWithFilter(filterForIpBucket(row.label, "src"))} />
        </AnalysisPanel>
        <AnalysisPanel title="目标 IP" tone="amber">
          <SimpleBarChart data={topDstIPs} color="bg-sky-500" onSelect={(row) => jumpWithFilter(filterForIpBucket(row.label, "dst"))} />
        </AnalysisPanel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <AnalysisPanel title="计算机名" tone="amber">
          <SimpleBarChart data={topComputerNames} color="bg-fuchsia-500" />
        </AnalysisPanel>
        <AnalysisPanel title="域名" tone="amber">
          <SimpleBarChart data={topDomains} color="bg-rose-500" onSelect={(row) => jumpWithFilter(filterForDomainBucket(row.label))} />
        </AnalysisPanel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <AnalysisPanel title="目标端口" tone="amber">
          <SimpleBarChart data={topDestPorts} color="bg-cyan-500" onSelect={(row) => jumpWithFilter(filterForPortBucket(row.label))} />
        </AnalysisPanel>
        <AnalysisPanel title="源端口" tone="amber">
          <SimpleBarChart data={topSrcPorts} color="bg-orange-500" onSelect={(row) => jumpWithFilter(filterForPortBucket(row.label))} />
        </AnalysisPanel>
      </div>
    </PageShell>
  );
}

export function buildStatsFromPackets(packets: Packet[]): GlobalTrafficStats {
  const timelineMap = new Map<string, number>();
  const protocolMap = new Map<string, number>();
  const talkerMap = new Map<string, number>();
  const srcIPMap = new Map<string, number>();
  const dstIPMap = new Map<string, number>();
  const domainMap = new Map<string, number>();
  const computerNameMap = new Map<string, number>();
  const dstPortMap = new Map<string, number>();
  const srcPortMap = new Map<string, number>();

  for (const p of packets) {
    const sec = (p.time || "").slice(0, 8) || "--:--:--";
    timelineMap.set(sec, (timelineMap.get(sec) ?? 0) + 1);

    const proto = String(p.displayProtocol || p.proto || "OTHER").toUpperCase();
    protocolMap.set(proto, (protocolMap.get(proto) ?? 0) + 1);

    const srcIP = String(p.src || "").trim();
    const dstIP = String(p.dst || "").trim();
    if (srcIP) {
      srcIPMap.set(srcIP, (srcIPMap.get(srcIP) ?? 0) + 1);
      talkerMap.set(srcIP, (talkerMap.get(srcIP) ?? 0) + 1);
    }
    if (dstIP) {
      dstIPMap.set(dstIP, (dstIPMap.get(dstIP) ?? 0) + 1);
      talkerMap.set(dstIP, (talkerMap.get(dstIP) ?? 0) + 1);
    }
    if (!srcIP && !dstIP) {
      talkerMap.set("unknown", (talkerMap.get("unknown") ?? 0) + 1);
    }

    const domain = extractDomain(p);
    if (domain) {
      domainMap.set(domain, (domainMap.get(domain) ?? 0) + 1);
    }

    const computerName = extractComputerName(p);
    if (computerName) {
      computerNameMap.set(computerName, (computerNameMap.get(computerName) ?? 0) + 1);
    }

    if (p.dstPort > 0) {
      const label = String(p.dstPort);
      dstPortMap.set(label, (dstPortMap.get(label) ?? 0) + 1);
    }
    if (p.srcPort > 0) {
      const label = String(p.srcPort);
      srcPortMap.set(label, (srcPortMap.get(label) ?? 0) + 1);
    }
  }

  const timeline = Array.from(timelineMap.entries())
    .sort((a, b) => (a[0] > b[0] ? 1 : -1))
    .map(([label, count]) => ({ label, count }));

  const protocolDist = Array.from(protocolMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  const topTalkers = Array.from(talkerMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  const topSrcIPs = Array.from(srcIPMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  const topDstIPs = Array.from(dstIPMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  const topDomains = Array.from(domainMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  const topComputerNames = Array.from(computerNameMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  const topDestPorts = Array.from(dstPortMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  const topSrcPorts = Array.from(srcPortMap.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count);

  return {
    totalPackets: packets.length,
    protocolKinds: protocolMap.size,
    timeline,
    protocolDist,
    topTalkers,
    topHostnames: topDomains,
    topDomains,
    topSrcIPs,
    topDstIPs,
    topComputerNames,
    topDestPorts,
    topSrcPorts,
  };
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

function SimpleBarChart({
  data,
  color,
  onSelect,
}: {
  data: Bucket[];
  color: string;
  onSelect?: (row: Bucket) => void;
}) {
  const max = Math.max(1, ...data.map((x) => x.count));

  if (data.length === 0) {
    return <AnalysisEmptyState>暂无数据</AnalysisEmptyState>;
  }

  return (
    <div className="max-h-[480px] overflow-auto pr-1">
      <div className="space-y-2">
        {data.map((row) => (
          <button
            key={row.label}
            type="button"
            onClick={() => onSelect?.(row)}
            className={`grid w-full grid-cols-[180px_1fr_64px] items-center gap-3 rounded-2xl px-2 py-2 text-left text-xs ${onSelect ? "transition-all hover:bg-amber-50/70 hover:shadow-sm" : ""}`}
          >
            <div className="truncate font-medium text-slate-500" title={row.label}>{row.label}</div>
            <div className="h-2 rounded-full bg-slate-100">
              <div className={`h-2 rounded ${color}`} style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }} />
            </div>
            <div className="text-right font-mono font-semibold text-slate-700">{row.count}</div>
          </button>
        ))}
      </div>
    </div>
  );
}

function filterForProtocolBucket(label: string) {
  const normalized = label.toUpperCase();
  switch (normalized) {
    case "HTTP":
      return "http";
    case "HTTPS":
    case "TLS":
    case "TLSV1.2":
    case "TLSV1.3":
      return "tls";
    case "DNS":
      return "dns";
    case "TCP":
      return "tcp";
    case "UDP":
      return "udp";
    case "ARP":
      return "arp";
    case "ICMP":
      return "icmp";
    case "ICMPV6":
      return "icmpv6";
    case "USB":
      return "usb";
    case "MODBUS":
    case "S7COMM":
    case "DNP3":
    case "CIP":
    case "BACNET":
    case "IEC104":
    case "OPCUA":
    case "PN_RT":
      return "modbus or s7comm or dnp3 or cip or bacnet or iec104 or opcua or pn_rt";
    case "CAN":
    case "J1939":
    case "DOIP":
    case "UDS":
      return "can or j1939 or doip or uds";
    case "RTP":
    case "RTCP":
    case "SIP":
    case "SDP":
      return "rtp or rtcp or sip or sdp";
    default:
      return normalized.toLowerCase();
  }
}

function filterForIpBucket(label: string, direction: "src" | "dst") {
  const target = label.trim();
  if (!target) return "";
  if (target.includes(":")) {
    return direction === "src" ? `ipv6.src == ${target}` : `ipv6.dst == ${target}`;
  }
  return direction === "src" ? `ip.src == ${target}` : `ip.dst == ${target}`;
}

function filterForDomainBucket(label: string) {
  const target = label.trim();
  if (!target) return "";
  return `http.host contains "${target}" or dns.qry.name contains "${target}" or tls.handshake.extensions_server_name contains "${target}"`;
}

function filterForPortBucket(label: string) {
  const port = label.trim();
  if (!port) return "";
  return `tcp.port == ${port} or udp.port == ${port}`;
}
