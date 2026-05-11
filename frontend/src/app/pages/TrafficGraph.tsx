import { useCallback, useMemo } from "react";
import { Activity, BarChart3, Clock3 } from "lucide-react";
import { useNavigate } from "react-router";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { StatusHint } from "../components/DesignSystem";
import { AnalysisPanel, AnalysisStatCard } from "../components/analysis/AnalysisPrimitives";
import { SimpleBarChart } from "../features/traffic/TrafficSimpleBarChart";
import { filterForDomainBucket, filterForIpBucket, filterForPortBucket, filterForProtocolBucket } from "../features/traffic/trafficGraphFilters";
import { useTrafficGraph } from "../features/traffic/useTrafficGraph";
import { useSentinel } from "../state/SentinelContext";

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
