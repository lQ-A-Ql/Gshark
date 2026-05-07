import { useCallback, useMemo } from "react";
import { Activity, BarChart3, Clock3 } from "lucide-react";
import { useNavigate } from "react-router";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
import { AnalysisEmptyState, AnalysisPanel, AnalysisStatCard } from "../components/analysis/AnalysisPrimitives";
import { useTrafficGraph } from "../features/traffic/useTrafficGraph";
import { useSentinel } from "../state/SentinelContext";

interface Bucket {
  label: string;
  count: number;
}

export default function TrafficGraph() {
  const navigate = useNavigate();
  const { totalPackets, backendConnected, isPreloadingCapture, fileMeta, setDisplayFilter, applyFilter, captureRevision } = useSentinel();
  const { stats, loading, error, refreshStats } = useTrafficGraph({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });

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

      {loading && <StatusHint tone="slate" className="mb-3">正在加载全局流量统计...</StatusHint>}

      {!loading && error && (
        <StatusHint tone="amber" className="mb-3 flex items-center justify-between">
          <span>{error}</span>
          <button className="rounded-full border border-amber-200 bg-white/90 px-3 py-1 font-semibold shadow-sm transition-all hover:bg-amber-100" onClick={() => refreshStats(true)}>重试</button>
        </StatusHint>
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
