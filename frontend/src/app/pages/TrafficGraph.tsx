import { useCallback, useMemo, useState } from "react";
import { BarChart3 } from "lucide-react";
import { useNavigate } from "react-router";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { useEvidence } from "../features/evidence/useEvidence";
import { TrafficGraphOverview, TrafficGraphPanels, type TrafficGraphSection } from "../features/traffic/TrafficGraphPanels";
import type { TrafficTimelineRangeSelection, TrafficTimelineSelection } from "../features/traffic/trafficTimeline";
import { useTrafficGraph } from "../features/traffic/useTrafficGraph";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { useFilter } from "../state/contexts/FilterContext";
import { usePacket } from "../state/contexts/PacketContext";

export default function TrafficGraph() {
  const [selectedSection, setSelectedSection] = useState<TrafficGraphSection>("overview");
  const [timelineSelection, setTimelineSelection] = useState<TrafficTimelineSelection>({
    hoveredLabel: null,
    lockedLabel: null,
    selectedRange: null,
  });
  const navigate = useNavigate();
  const { backendConnected } = useBackend();
  const { isPreloadingCapture, fileMeta, captureRevision } = useCapture();
  const { setDisplayFilter, applyFilter } = useFilter();
  const { totalPackets } = usePacket();
  const { stats, loading, error, refreshStats } = useTrafficGraph({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
  });
  const {
    evidence: huntingEvidence,
    loading: evidenceLoading,
    error: evidenceError,
  } = useEvidence({
    backendConnected,
    isPreloadingCapture,
    filePath: fileMeta.path,
    totalPackets,
    captureRevision,
    modules: ["hunting"],
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
  const topTalkers = useMemo(() => stats.topTalkers || [], [stats.topTalkers]);
  const topConversations = useMemo(() => stats.topConversations || [], [stats.topConversations]);
  const protocolHierarchy = useMemo(() => stats.protocolHierarchy || [], [stats.protocolHierarchy]);

  const jumpWithFilter = useCallback(
    (filter: string) => {
      if (!filter.trim()) return;
      setDisplayFilter(filter);
      applyFilter(filter);
      navigate("/");
    },
    [applyFilter, navigate, setDisplayFilter],
  );

  const setTimelineHoverLabel = useCallback((label: string | null) => {
    setTimelineSelection((current) => ({ ...current, hoveredLabel: label }));
  }, []);

  const setTimelineLockedLabel = useCallback((label: string | null) => {
    setTimelineSelection((current) => ({ ...current, lockedLabel: label }));
  }, []);

  const setTimelineRange = useCallback((range: TrafficTimelineRangeSelection | null) => {
    setTimelineSelection((current) => ({ ...current, selectedRange: range }));
  }, []);

  const clearTimelineSelection = useCallback(() => {
    setTimelineSelection({ hoveredLabel: null, lockedLabel: null, selectedRange: null });
  }, []);

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
        topTalkers={topTalkers}
        topConversations={topConversations}
        protocolHierarchy={protocolHierarchy}
        evidenceRecords={huntingEvidence}
        evidenceLoading={evidenceLoading}
        evidenceError={evidenceError || null}
        selectedSection={selectedSection}
        timelineSelection={timelineSelection}
        onSelectSection={setSelectedSection}
        onTimelineHoverLabel={setTimelineHoverLabel}
        onTimelineLockedLabel={setTimelineLockedLabel}
        onTimelineRangeSelect={setTimelineRange}
        onTimelineClearSelection={clearTimelineSelection}
        onJumpFilter={jumpWithFilter}
      />
    </PageShell>
  );
}
