import { useCallback, useMemo } from "react";
import { BarChart3 } from "lucide-react";
import { useNavigate } from "react-router";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { TrafficGraphOverview, TrafficGraphPanels } from "../features/traffic/TrafficGraphPanels";
import { useTrafficGraph } from "../features/traffic/useTrafficGraph";
import { useSentinel } from "../state/SentinelContext";

export default function TrafficGraph() {
  const navigate = useNavigate();
  const {
    totalPackets,
    backendConnected,
    isPreloadingCapture,
    fileMeta,
    setDisplayFilter,
    applyFilter,
    captureRevision,
  } = useSentinel();
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
  const topDomains = useMemo(
    () => stats.topDomains || stats.topHostnames || [],
    [stats.topDomains, stats.topHostnames],
  );
  const topDestPorts = useMemo(() => stats.topDestPorts || [], [stats.topDestPorts]);
  const topSrcPorts = useMemo(() => stats.topSrcPorts || [], [stats.topSrcPorts]);

  const jumpWithFilter = useCallback(
    (filter: string) => {
      if (!filter.trim()) return;
      setDisplayFilter(filter);
      applyFilter(filter);
      navigate("/");
    },
    [applyFilter, navigate, setDisplayFilter],
  );
  return (
    <PageShell>
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

      <TrafficGraphOverview
        error={error}
        loading={loading}
        stats={stats}
        timeline={timeline}
        onRetry={() => refreshStats(true)}
      />
      <TrafficGraphPanels
        protocolDist={protocolDist}
        timeline={timeline}
        topComputerNames={topComputerNames}
        topDestPorts={topDestPorts}
        topDomains={topDomains}
        topDstIPs={topDstIPs}
        topSrcIPs={topSrcIPs}
        topSrcPorts={topSrcPorts}
        onJumpFilter={jumpWithFilter}
      />
    </PageShell>
  );
}
