import { BarChart3 } from "lucide-react";
import { AnalysisHero } from "../components/AnalysisHero";
import { PageShell } from "../components/PageShell";
import { TrafficGraphOverview, TrafficGraphPanels } from "../features/traffic/TrafficGraphPanels";
import type { TrafficGraphPageState } from "./useTrafficGraphPageState";

export function TrafficGraphLayout(state: TrafficGraphPageState) {
  const stats = state.stats;
  const topDomains = stats.topDomains || stats.topHostnames || [];
  return (
    <PageShell>
      <AnalysisHero
        icon={<BarChart3 className="h-5 w-5" />}
        title="流量图分析"
        subtitle="GLOBAL TRAFFIC OVERVIEW"
        description="统一查看全局协议分布、时序趋势、热点 IP、端口与域名，适合作为进入其他专题分析前的总览视角。"
        tags={state.trafficTags}
        tagsLabel="视图层"
        theme="amber"
        onRefresh={() => state.refreshStats(true)}
      />
      <TrafficGraphOverview error={state.error} loading={state.loading} stats={stats} timeline={stats.timeline} onRetry={() => state.refreshStats(true)} />
      <TrafficGraphPanels
        protocolDist={stats.protocolDist}
        timeline={stats.timeline}
        topComputerNames={stats.topComputerNames || []}
        topDestPorts={stats.topDestPorts || []}
        topDomains={topDomains}
        topDstIPs={stats.topDstIPs || []}
        topSrcIPs={stats.topSrcIPs || []}
        topSrcPorts={stats.topSrcPorts || []}
        topTalkers={stats.topTalkers || []}
        topConversations={stats.topConversations || []}
        protocolHierarchy={stats.protocolHierarchy || []}
        evidenceRecords={state.evidenceRecords}
        evidenceLoading={state.evidenceLoading}
        evidenceError={state.evidenceError}
        selectedSection={state.selectedSection}
        timelineSelection={state.timelineSelection}
        onSelectSection={state.setSelectedSection}
        onTimelineHoverLabel={state.setTimelineHoverLabel}
        onTimelineLockedLabel={state.setTimelineLockedLabel}
        onTimelineRangeSelect={state.setTimelineRange}
        onTimelineClearSelection={state.clearTimelineSelection}
        onJumpFilter={state.jumpWithFilter}
      />
    </PageShell>
  );
}
