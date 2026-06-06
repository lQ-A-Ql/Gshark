import type { TrafficConversation } from "../../core/types";
import type { TopologyEdge } from "./TrafficTopologyGraph";
import type { AnalysisBucket, TrafficGraphSection } from "./trafficGraphPanelTypes";
import { filterForDomainBucket, filterForIpBucket, filterForPortBucket } from "./trafficGraphFilters";

export const GLOBAL_SELECTION_WARNING = "已选择时间窗口/时间点；当前卡片仍展示全局统计，窗口统计待接入。";

export const trafficSectionGroups: Array<{
  label: string;
  items: Array<{ id: TrafficGraphSection; title: string; description: string }>;
}> = [
  {
    label: "分析视图",
    items: [
      { id: "overview", title: "流量概览", description: "总包数、协议种类与时间窗口" },
      { id: "trend", title: "流量时间线", description: "峰值走势、事件轨与窗口选择" },
      { id: "topology", title: "通信拓扑", description: "仅基于显式会话边构建图谱" },
      { id: "protocols", title: "协议分布", description: "协议排行与层级树联合查看" },
      { id: "conversations", title: "会话排行", description: "源到目标会话热度排行" },
      { id: "talkers", title: "端点排行", description: "端点、域名、端口等热点实体" },
    ],
  },
];

export function buildTopologyEdges(conversations: TrafficConversation[]): TopologyEdge[] {
  return conversations.map((conversation) => ({ src: conversation.src, dst: conversation.dst, count: conversation.count }));
}

export function buildConversationBuckets(conversations: TrafficConversation[]): AnalysisBucket[] {
  return conversations.map((conversation) => ({ label: `${conversation.src} → ${conversation.dst}`, count: conversation.count }));
}

export function buildTalkerPanels(input: {
  topComputerNames: AnalysisBucket[];
  topDestPorts: AnalysisBucket[];
  topDomains: AnalysisBucket[];
  topDstIPs: AnalysisBucket[];
  topSrcIPs: AnalysisBucket[];
  topSrcPorts: AnalysisBucket[];
  topTalkers: AnalysisBucket[];
}) {
  return [
    { title: "源 IP", data: input.topSrcIPs, color: "bg-violet-500", onSelect: (label: string) => filterForIpBucket(label, "src") },
    { title: "目标 IP", data: input.topDstIPs, color: "bg-sky-500", onSelect: (label: string) => filterForIpBucket(label, "dst") },
    { title: "端点热点", data: input.topTalkers, color: "bg-amber-500" },
    { title: "计算机名", data: input.topComputerNames, color: "bg-fuchsia-500" },
    { title: "域名", data: input.topDomains, color: "bg-rose-500", onSelect: filterForDomainBucket },
    { title: "目标端口", data: input.topDestPorts, color: "bg-cyan-500", onSelect: filterForPortBucket },
    { title: "源端口", data: input.topSrcPorts, color: "bg-orange-500", onSelect: filterForPortBucket },
  ];
}
