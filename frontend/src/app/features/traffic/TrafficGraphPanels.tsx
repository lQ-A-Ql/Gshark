import type { TrafficProtocolTreeNode, TrafficBucket } from "../../core/types";
import { AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import { SimpleBarChart } from "./TrafficSimpleBarChart";
import { TrafficAreaChart } from "./TrafficAreaChart";
import { TrafficTopologyGraph, type TopologyEdge } from "./TrafficTopologyGraph";
import { TrafficProtocolTree } from "./TrafficProtocolTree";
import {
  filterForDomainBucket,
  filterForIpBucket,
  filterForPortBucket,
  filterForProtocolBucket,
} from "./trafficGraphFilters";

export { TrafficGraphOverview } from "./TrafficGraphOverview";

type AnalysisBucket = TrafficBucket;

type TrafficGraphPanelsProps = {
  protocolDist: AnalysisBucket[];
  timeline: AnalysisBucket[];
  topComputerNames: AnalysisBucket[];
  topDestPorts: AnalysisBucket[];
  topDomains: AnalysisBucket[];
  topDstIPs: AnalysisBucket[];
  topSrcIPs: AnalysisBucket[];
  topSrcPorts: AnalysisBucket[];
  topTalkers: AnalysisBucket[];
  protocolHierarchy?: TrafficProtocolTreeNode[];
  onJumpFilter: (filter: string) => void;
};

export function TrafficGraphPanels({
  protocolDist,
  timeline,
  topComputerNames,
  topDestPorts,
  topDomains,
  topDstIPs,
  topSrcIPs,
  topSrcPorts,
  topTalkers,
  protocolHierarchy,
  onJumpFilter,
}: TrafficGraphPanelsProps) {
  const timelinePoints = timeline.map((t) => ({ label: t.label, count: t.count }));
  const topologyEdges: TopologyEdge[] = topTalkers.map((t) => {
    const parts = t.label.split(" → ");
    return { src: parts[0] ?? t.label, dst: parts[1] ?? "", count: t.count };
  }).filter((e) => e.src && e.dst);

  const chartPanels = [
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
    <div className="mt-0 grid grid-cols-1 gap-0">
      <AnalysisPanel title="每秒流量趋势" tone="amber">
        <TrafficAreaChart data={timelinePoints} height={180} color="#3b82f6" />
      </AnalysisPanel>

      <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
        <AnalysisPanel title="会话拓扑 (源 → 目标)" tone="amber">
          <TrafficTopologyGraph edges={topologyEdges} maxNodes={16} height={300} />
        </AnalysisPanel>
        <AnalysisPanel title="协议层级树" tone="amber">
          <TrafficProtocolTree data={protocolHierarchy ?? []} />
        </AnalysisPanel>
      </div>

      <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
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
    </div>
  );
}
