import { Activity, BarChart3, Clock3 } from "lucide-react";
import type { GlobalTrafficStats } from "../../core/types";
import { StatusHint } from "../../components/DesignSystem";
import { AnalysisPanel, type AnalysisBucket } from "../../components/analysis/AnalysisPrimitives";
import { AnalysisStatCard } from "../../components/analysis/AnalysisPrimitives";
import { SimpleBarChart } from "./TrafficSimpleBarChart";
import {
  filterForDomainBucket,
  filterForIpBucket,
  filterForPortBucket,
  filterForProtocolBucket,
} from "./trafficGraphFilters";

type TrafficGraphPanelsProps = {
  protocolDist: AnalysisBucket[];
  timeline: AnalysisBucket[];
  topComputerNames: AnalysisBucket[];
  topDestPorts: AnalysisBucket[];
  topDomains: AnalysisBucket[];
  topDstIPs: AnalysisBucket[];
  topSrcIPs: AnalysisBucket[];
  topSrcPorts: AnalysisBucket[];
  onJumpFilter: (filter: string) => void;
};

type TrafficGraphOverviewProps = {
  error: string;
  loading: boolean;
  stats: GlobalTrafficStats;
  timeline: AnalysisBucket[];
  onRetry: () => void;
};

export function TrafficGraphOverview({ error, loading, stats, timeline, onRetry }: TrafficGraphOverviewProps) {
  const timeWindow = timeline.length > 0 ? `${timeline[0].label} ~ ${timeline[timeline.length - 1].label}` : "--";

  return (
    <>
      {loading && (
        <StatusHint tone="slate" className="mb-3">
          正在加载全局流量统计...
        </StatusHint>
      )}
      {!loading && error ? (
        <StatusHint tone="amber" className="mb-3 flex items-center justify-between">
          <span>{error}</span>
          <button
            className="border border-amber-200 bg-amber-50/80 px-3 py-1 font-semibold transition-all hover:bg-amber-100"
            onClick={onRetry}
          >
            重试
          </button>
        </StatusHint>
      ) : null}
      <div className="gshark-tile-grid grid grid-cols-1 lg:grid-cols-3">
        <AnalysisStatCard
          title="总包数"
          value={stats.totalPackets.toLocaleString()}
          icon={<Activity className="h-4 w-4 text-emerald-600" />}
          tone="amber"
        />
        <AnalysisStatCard
          title="协议种类"
          value={String(stats.protocolKinds)}
          icon={<BarChart3 className="h-4 w-4 text-indigo-600" />}
          tone="amber"
        />
        <AnalysisStatCard
          title="时间窗口"
          value={timeWindow}
          icon={<Clock3 className="h-4 w-4 text-amber-600" />}
          tone="amber"
        />
      </div>
    </>
  );
}

export function TrafficGraphPanels({
  protocolDist,
  timeline,
  topComputerNames,
  topDestPorts,
  topDomains,
  topDstIPs,
  topSrcIPs,
  topSrcPorts,
  onJumpFilter,
}: TrafficGraphPanelsProps) {
  const chartPanels = [
    { title: "每秒流量趋势", data: timeline, color: "bg-blue-500" },
    { title: "协议分布", data: protocolDist, color: "bg-emerald-500", onSelect: filterForProtocolBucket },
    {
      title: "源 IP",
      data: topSrcIPs,
      color: "bg-violet-500",
      onSelect: (label: string) => filterForIpBucket(label, "src"),
    },
    {
      title: "目标 IP",
      data: topDstIPs,
      color: "bg-sky-500",
      onSelect: (label: string) => filterForIpBucket(label, "dst"),
    },
    { title: "计算机名", data: topComputerNames, color: "bg-fuchsia-500" },
    { title: "域名", data: topDomains, color: "bg-rose-500", onSelect: filterForDomainBucket },
    { title: "目标端口", data: topDestPorts, color: "bg-cyan-500", onSelect: filterForPortBucket },
    { title: "源端口", data: topSrcPorts, color: "bg-orange-500", onSelect: filterForPortBucket },
  ];

  return (
    <div className="mt-0 grid grid-cols-1 gap-0 xl:grid-cols-2">
      {chartPanels.map((panel) => (
        <AnalysisPanel key={panel.title} title={panel.title} tone="amber">
          <SimpleBarChart
            data={panel.data}
            color={panel.color}
            onSelect={panel.onSelect ? (row) => onJumpFilter(panel.onSelect?.(row.label) ?? "") : undefined}
          />
        </AnalysisPanel>
      ))}
    </div>
  );
}
