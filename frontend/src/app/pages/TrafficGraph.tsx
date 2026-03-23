import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Activity, BarChart3, Clock3 } from "lucide-react";
import { bridge, type GlobalTrafficStats } from "../integrations/wailsBridge";
import { useSentinel } from "../state/SentinelContext";
import type { Packet } from "../core/types";

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
  const { totalPackets, backendConnected, isPreloadingCapture, fileMeta } = useSentinel();
  const captureCacheKey = useMemo(() => {
    if (!fileMeta.path) return "";
    return `${fileMeta.path}::${totalPackets}`;
  }, [fileMeta.path, totalPackets]);
  const [stats, setStats] = useState<GlobalTrafficStats>(EMPTY_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

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
    void bridge
      .getGlobalTrafficStats()
      .then((payload) => {
        if (captureCacheKey) {
          trafficStatsCache.set(captureCacheKey, payload);
        }
        setStats(payload);
      })
      .catch(async (e) => {
        // Backward compatibility for old backend without global stats endpoint.
        try {
          const packets = await bridge.listPackets();
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
        setLoading(false);
      });
  }, [backendConnected, captureCacheKey]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    refreshStats();
  }, [refreshStats, isPreloadingCapture]);

  const timeline = useMemo(() => stats.timeline, [stats.timeline]);
  const protocolDist = useMemo(() => stats.protocolDist, [stats.protocolDist]);
  const topSrcIPs = useMemo(() => stats.topSrcIPs || [], [stats.topSrcIPs]);
  const topDstIPs = useMemo(() => stats.topDstIPs || [], [stats.topDstIPs]);
  const topComputerNames = useMemo(() => stats.topComputerNames || [], [stats.topComputerNames]);
  const topDomains = useMemo(() => stats.topDomains || stats.topHostnames || [], [stats.topDomains, stats.topHostnames]);
  const topDestPorts = useMemo(() => stats.topDestPorts || [], [stats.topDestPorts]);
  const topSrcPorts = useMemo(() => stats.topSrcPorts || [], [stats.topSrcPorts]);

  return (
    <div className="flex h-full flex-col overflow-auto bg-background p-4 text-foreground">
      <div className="mb-4 flex items-center gap-2 text-lg font-semibold text-foreground">
        <BarChart3 className="h-5 w-5 text-blue-600" /> 流量图分析
        <span className="ml-2 rounded border border-border bg-accent px-2 py-0.5 text-xs font-medium text-muted-foreground">全局视图 (忽略过滤器)</span>
        <button className="ml-2 rounded border border-border bg-card px-2 py-0.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground" onClick={() => refreshStats(true)}>
          刷新
        </button>
      </div>

      {loading && (
        <div className="mb-3 rounded border border-border bg-card px-3 py-2 text-xs text-muted-foreground">正在加载全局流量统计...</div>
      )}

      {!loading && error && (
        <div className="mb-3 flex items-center justify-between rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-700">
          <span>{error}</span>
          <button className="rounded border border-amber-300 bg-white px-2 py-0.5 hover:bg-amber-100" onClick={() => refreshStats(true)}>重试</button>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <StatCard title="总包数" value={stats.totalPackets.toLocaleString()} icon={<Activity className="h-4 w-4 text-emerald-600" />} />
        <StatCard title="协议种类" value={String(stats.protocolKinds)} icon={<BarChart3 className="h-4 w-4 text-indigo-600" />} />
        <StatCard title="时间窗口" value={timeline.length > 0 ? `${timeline[0].label} ~ ${timeline[timeline.length - 1].label}` : "--"} icon={<Clock3 className="h-4 w-4 text-amber-600" />} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="每秒流量趋势">
          <SimpleBarChart data={timeline} color="bg-blue-500" />
        </Panel>
        <Panel title="协议分布">
          <SimpleBarChart data={protocolDist} color="bg-emerald-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="源 IP">
          <SimpleBarChart data={topSrcIPs} color="bg-violet-500" />
        </Panel>
        <Panel title="目标 IP">
          <SimpleBarChart data={topDstIPs} color="bg-sky-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="计算机名">
          <SimpleBarChart data={topComputerNames} color="bg-fuchsia-500" />
        </Panel>
        <Panel title="域名">
          <SimpleBarChart data={topDomains} color="bg-rose-500" />
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title="目标端口">
          <SimpleBarChart data={topDestPorts} color="bg-cyan-500" />
        </Panel>
        <Panel title="源端口">
          <SimpleBarChart data={topSrcPorts} color="bg-orange-500" />
        </Panel>
      </div>
    </div>
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

function StatCard({ title, value, icon }: { title: string; value: string; icon: ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
        <span>{title}</span>
        {icon}
      </div>
      <div className="text-lg font-semibold text-foreground">{value}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="mb-3 text-sm font-semibold text-foreground">{title}</div>
      {children}
    </div>
  );
}

function SimpleBarChart({ data, color }: { data: Bucket[]; color: string }) {
  const max = Math.max(1, ...data.map((x) => x.count));

  if (data.length === 0) {
    return <div className="rounded border border-dashed border-border px-3 py-6 text-center text-xs text-muted-foreground">暂无数据</div>;
  }

  return (
    <div className="max-h-[480px] overflow-auto pr-1">
      <div className="space-y-2">
        {data.map((row) => (
          <div key={row.label} className="grid grid-cols-[180px_1fr_64px] items-center gap-2 text-xs">
            <div className="truncate text-muted-foreground" title={row.label}>{row.label}</div>
            <div className="h-2 rounded bg-accent">
              <div className={`h-2 rounded ${color}`} style={{ width: `${Math.max(2, (row.count / max) * 100)}%` }} />
            </div>
            <div className="text-right font-mono text-foreground">{row.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
