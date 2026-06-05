import { useMemo } from "react";
import type { JSX } from "react";
import { StatusHint } from "../../components/DesignSystem";
import { cn } from "../../components/ui/utils";
import type { TrafficBucket, TrafficConversation, TrafficProtocolTreeNode } from "../../core/types";
import type { UnifiedEvidenceRecord } from "../../core/evidenceTypes";
import { AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import { SimpleBarChart } from "./TrafficSimpleBarChart";
import { TrafficAreaChart } from "./TrafficAreaChart";
import { TrafficTopologyGraph, type TopologyEdge } from "./TrafficTopologyGraph";
import { TrafficProtocolTree } from "./TrafficProtocolTree";
import { TrafficTimelineSummary } from "./TrafficTimelineSummary";
import { TrafficTimelineTrack } from "./TrafficTimelineTrack";
import { TrafficTimelineEvidenceTrack } from "./TrafficTimelineEvidenceTrack";
import { buildTrafficTimelineEvidence } from "./trafficTimelineEvidence";
import { buildTrafficTimelineEvents } from "./trafficTimelineEvents";
import { normalizeTrafficTimelineBuckets, type TrafficTimelineRangeSelection, type TrafficTimelineSelection } from "./trafficTimeline";
import {
  filterForDomainBucket,
  filterForIpBucket,
  filterForPortBucket,
  filterForProtocolBucket,
} from "./trafficGraphFilters";

export { TrafficGraphOverview } from "./TrafficGraphOverview";

type AnalysisBucket = TrafficBucket;

const GLOBAL_SELECTION_WARNING = "已选择时间窗口/时间点；当前卡片仍展示全局统计，窗口统计待接入。";

export type TrafficGraphSection = "overview" | "trend" | "topology" | "protocols" | "conversations" | "talkers";

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
  topConversations: TrafficConversation[];
  protocolHierarchy?: TrafficProtocolTreeNode[];
  evidenceRecords?: UnifiedEvidenceRecord[];
  evidenceLoading?: boolean;
  evidenceError?: string | null;
  selectedSection: TrafficGraphSection;
  timelineSelection: TrafficTimelineSelection;
  onSelectSection: (section: TrafficGraphSection) => void;
  onTimelineHoverLabel: (label: string | null) => void;
  onTimelineLockedLabel: (label: string | null) => void;
  onTimelineRangeSelect: (range: TrafficTimelineRangeSelection | null) => void;
  onTimelineClearSelection: () => void;
  onJumpFilter: (filter: string) => void;
};

const trafficSectionGroups: Array<{
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
  topConversations,
  protocolHierarchy,
  evidenceRecords = [],
  evidenceLoading = false,
  evidenceError = null,
  selectedSection,
  timelineSelection,
  onSelectSection,
  onTimelineHoverLabel,
  onTimelineLockedLabel,
  onTimelineRangeSelect,
  onTimelineClearSelection,
  onJumpFilter,
}: TrafficGraphPanelsProps) {
  const timelinePoints = useMemo(
    () => normalizeTrafficTimelineBuckets(timeline).map((item) => ({ label: item.label, count: item.count })),
    [timeline],
  );

  const topologyEdges = useMemo<TopologyEdge[]>(
    () =>
      topConversations.map((conversation) => ({
        src: conversation.src,
        dst: conversation.dst,
        count: conversation.count,
      })),
    [topConversations],
  );

  const timelineEvents = useMemo(() => buildTrafficTimelineEvents(timelinePoints), [timelinePoints]);
  const timelineEvidence = useMemo(
    () => buildTrafficTimelineEvidence(timelinePoints, evidenceRecords),
    [timelinePoints, evidenceRecords],
  );
  const hasTimelineSelection = Boolean(
    timelineSelection.hoveredLabel || timelineSelection.lockedLabel || timelineSelection.selectedRange,
  );
  const topologyLinkedContextLabel = timelineSelection.selectedRange
    ? `${timelineSelection.selectedRange.startLabel} ~ ${timelineSelection.selectedRange.endLabel}`
    : timelineSelection.lockedLabel ?? timelineSelection.hoveredLabel;

  const topConversationBuckets = useMemo(
    () => topConversations.map((conversation) => ({ label: `${conversation.src} → ${conversation.dst}`, count: conversation.count })),
    [topConversations],
  );

  const chartPanels = useMemo(
    () => [
      { title: "源 IP", data: topSrcIPs, color: "bg-violet-500", onSelect: (label: string) => filterForIpBucket(label, "src") },
      { title: "目标 IP", data: topDstIPs, color: "bg-sky-500", onSelect: (label: string) => filterForIpBucket(label, "dst") },
      { title: "端点热点", data: topTalkers, color: "bg-amber-500" },
      { title: "计算机名", data: topComputerNames, color: "bg-fuchsia-500" },
      { title: "域名", data: topDomains, color: "bg-rose-500", onSelect: filterForDomainBucket },
      { title: "目标端口", data: topDestPorts, color: "bg-cyan-500", onSelect: filterForPortBucket },
      { title: "源端口", data: topSrcPorts, color: "bg-orange-500", onSelect: filterForPortBucket },
    ],
    [topSrcIPs, topDstIPs, topTalkers, topComputerNames, topDomains, topDestPorts, topSrcPorts],
  );

  const selectedSectionMeta = useMemo(
    () => trafficSectionGroups.flatMap((group) => group.items).find((item) => item.id === selectedSection),
    [selectedSection],
  );

  const selectionInfoStrip = hasTimelineSelection ? (
    <StatusHint tone="blue" className="mb-3 text-xs">
      {GLOBAL_SELECTION_WARNING}
    </StatusHint>
  ) : null;

  let content: JSX.Element;
  switch (selectedSection) {
    case "trend":
      content = (
        <AnalysisPanel title="流量时间线" tone="amber">
          <div className="space-y-3">
            <TrafficAreaChart
              data={timelinePoints}
              height={220}
              color="var(--color-chart-2)"
              hoveredLabel={timelineSelection.hoveredLabel}
              lockedLabel={timelineSelection.lockedLabel}
              selectedRange={timelineSelection.selectedRange}
              onHoverPoint={(point) => onTimelineHoverLabel(point?.label ?? null)}
              onSelectPoint={(point) =>
                onTimelineLockedLabel(point.label === timelineSelection.lockedLabel ? null : point.label)
              }
              onSelectRange={onTimelineRangeSelect}
            />
            <TrafficTimelineTrack
              events={timelineEvents}
              hoveredLabel={timelineSelection.hoveredLabel}
              lockedLabel={timelineSelection.lockedLabel}
              onHoverEvent={onTimelineHoverLabel}
              onSelectEvent={(label) => onTimelineLockedLabel(label === timelineSelection.lockedLabel ? null : label)}
            />
            {evidenceLoading ? (
              <StatusHint tone="blue" className="text-xs">正在加载 Evidence / YARA 证据...</StatusHint>
            ) : evidenceError ? (
              <StatusHint tone="amber" className="text-xs">Evidence 加载失败，流量时间线仍可用：{evidenceError}</StatusHint>
            ) : (
              <TrafficTimelineEvidenceTrack
                events={timelineEvidence.events}
                hoveredLabel={timelineSelection.hoveredLabel}
                lockedLabel={timelineSelection.lockedLabel}
                onHoverEvent={onTimelineHoverLabel}
                onSelectEvent={(label) => onTimelineLockedLabel(label === timelineSelection.lockedLabel ? null : label)}
              />
            )}
            <TrafficTimelineSummary
              selection={timelineSelection}
              points={timelinePoints}
              evidenceEvents={timelineEvidence.events}
              unplacedEvidenceCount={timelineEvidence.unplacedRecords.length}
              onClearSelection={onTimelineClearSelection}
            />
          </div>
        </AnalysisPanel>
      );
      break;
    case "topology":
      content = (
        <AnalysisPanel title="会话拓扑 (源 → 目标)" tone="amber">
          {selectionInfoStrip}
          <TrafficTopologyGraph
            edges={topologyEdges}
            maxNodes={16}
            height={360}
            linkedContextLabel={topologyLinkedContextLabel}
          />
        </AnalysisPanel>
      );
      break;
    case "protocols":
      content = (
        <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
          <AnalysisPanel title="协议分布" tone="amber">
            {selectionInfoStrip}
            <SimpleBarChart
              data={protocolDist}
              color="bg-emerald-500"
              onSelect={(row) => onJumpFilter(filterForProtocolBucket(row.label) ?? "")}
            />
          </AnalysisPanel>
          <AnalysisPanel title="协议层级树" tone="amber">
            {selectionInfoStrip}
            <TrafficProtocolTree data={protocolHierarchy ?? []} />
          </AnalysisPanel>
        </div>
      );
      break;
    case "conversations":
      content = (
        <AnalysisPanel title="会话排行" tone="amber">
          {selectionInfoStrip}
          <SimpleBarChart data={topConversationBuckets} color="bg-amber-500" />
        </AnalysisPanel>
      );
      break;
    case "talkers":
      content = (
        <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
          {chartPanels.map((panel) => (
            <AnalysisPanel key={panel.title} title={panel.title} tone="amber">
              {selectionInfoStrip}
              <SimpleBarChart
                data={panel.data}
                color={panel.color}
                onSelect={panel.onSelect ? (row) => onJumpFilter(panel.onSelect?.(row.label) ?? "") : undefined}
              />
            </AnalysisPanel>
          ))}
        </div>
      );
      break;
    case "overview":
    default:
      content = (
        <div className="meow-tile p-5">
          <div className="grid gap-2 text-sm text-slate-600 md:grid-cols-3">
            <div className="rounded-sm border border-[var(--meow-tile-divider)] bg-white/70 px-3 py-2">
              当前流量图按分析视图拆分，避免一次性渲染全部重型卡片。
            </div>
            <div className="rounded-sm border border-[var(--meow-tile-divider)] bg-white/70 px-3 py-2">
              每秒趋势按可解析秒级时间排序，过滤空值与异常时间点。
            </div>
            <div className="rounded-sm border border-[var(--meow-tile-divider)] bg-white/70 px-3 py-2">
              拓扑关系仅来自 `topConversations`，不会回退解析端点标签伪造边。
            </div>
          </div>
        </div>
      );
      break;
  }

  return (
    <div className="meow-aurora-surface flex min-h-0 flex-1 overflow-hidden border border-[var(--meow-tile-divider)]">
      <nav className="flex w-56 shrink-0 flex-col overflow-y-auto border-r border-[var(--meow-tile-divider)]">
        <div className="flex flex-col gap-1 p-3">
          {trafficSectionGroups.map((group) => (
            <div key={group.label} className="mb-1">
              <div className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400">
                {group.label}
              </div>
              {group.items.map((item) => {
                const isActive = item.id === selectedSection;
                return (
                  <button
                    key={item.id}
                    type="button"
                    aria-pressed={isActive}
                    onClick={() => onSelectSection(item.id)}
                    className={cn(
                      "flex w-full flex-col gap-0.5 rounded-sm px-2 py-2 text-left transition-all",
                      isActive
                        ? "bg-cyan-50/30 text-cyan-900 shadow-[inset_0_0_0_1px_rgba(6,182,212,0.18)]"
                        : "text-slate-600 hover:bg-slate-50/40 hover:text-slate-800",
                    )}
                  >
                    <span className="text-[13px] font-semibold">{item.title}</span>
                    <span className="text-[11px] text-slate-400">{item.description}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
      </nav>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div className="border-b border-[var(--meow-tile-divider)] px-5 py-4">
          <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-400">Traffic Graph</div>
          <div className="mt-1 text-lg font-semibold text-slate-900">{selectedSectionMeta?.title ?? "流量概览"}</div>
          <div className="mt-1 text-sm text-slate-500">{selectedSectionMeta?.description ?? "聚焦当前流量分析主视图。"}</div>
        </div>
        <div className="min-h-0 flex-1 overflow-auto">{content}</div>
      </div>
    </div>
  );
}
