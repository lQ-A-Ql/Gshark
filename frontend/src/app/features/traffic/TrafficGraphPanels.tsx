import { useMemo } from "react";
import { normalizeTrafficTimelineBuckets } from "./trafficTimeline";
import { TrafficGraphPanelHeader } from "./TrafficGraphPanelHeader";
import { TrafficGraphSectionNav } from "./TrafficGraphSectionNav";
import { TrafficGraphSelectedPanel } from "./TrafficGraphSelectedPanel";
import {
  buildConversationBuckets,
  buildTalkerPanels,
  buildTopologyEdges,
  trafficSectionGroups,
} from "./trafficGraphPanelModel";
import type { TrafficGraphPanelsProps } from "./trafficGraphPanelTypes";
export type { TrafficGraphSection } from "./trafficGraphPanelTypes";
export { TrafficGraphOverview } from "./TrafficGraphOverview";

export function TrafficGraphPanels(props: TrafficGraphPanelsProps) {
  const timelinePoints = useMemo(
    () => normalizeTrafficTimelineBuckets(props.timeline).map((item) => ({ label: item.label, count: item.count })),
    [props.timeline],
  );
  const topologyEdges = useMemo(() => buildTopologyEdges(props.topConversations), [props.topConversations]);
  const conversationBuckets = useMemo(() => buildConversationBuckets(props.topConversations), [props.topConversations]);
  const talkerPanels = useMemo(
    () =>
      buildTalkerPanels({
        topComputerNames: props.topComputerNames,
        topDestPorts: props.topDestPorts,
        topDomains: props.topDomains,
        topDstIPs: props.topDstIPs,
        topSrcIPs: props.topSrcIPs,
        topSrcPorts: props.topSrcPorts,
        topTalkers: props.topTalkers,
      }),
    [props.topComputerNames, props.topDestPorts, props.topDomains, props.topDstIPs, props.topSrcIPs, props.topSrcPorts, props.topTalkers],
  );
  const selectedSectionMeta = useMemo(
    () => trafficSectionGroups.flatMap((group) => group.items).find((item) => item.id === props.selectedSection),
    [props.selectedSection],
  );
  const hasTimelineSelection = Boolean(
    props.timelineSelection.hoveredLabel || props.timelineSelection.lockedLabel || props.timelineSelection.selectedRange,
  );
  const linkedContextLabel = props.timelineSelection.selectedRange
    ? `${props.timelineSelection.selectedRange.startLabel} ~ ${props.timelineSelection.selectedRange.endLabel}`
    : props.timelineSelection.lockedLabel ?? props.timelineSelection.hoveredLabel;

  return (
    <div className="meow-aurora-surface flex min-h-0 flex-1 overflow-hidden border border-[var(--meow-tile-divider)]">
      <TrafficGraphSectionNav selectedSection={props.selectedSection} onSelectSection={props.onSelectSection} />
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <TrafficGraphPanelHeader
          title={selectedSectionMeta?.title ?? "流量概览"}
          description={selectedSectionMeta?.description ?? "聚焦当前流量分析主视图。"}
        />
        <div className="min-h-0 flex-1 overflow-auto">
          <TrafficGraphSelectedPanel
            {...props}
            conversationBuckets={conversationBuckets}
            hasTimelineSelection={hasTimelineSelection}
            linkedContextLabel={linkedContextLabel}
            talkerPanels={talkerPanels}
            timelinePoints={timelinePoints}
            topologyEdges={topologyEdges}
          />
        </div>
      </div>
    </div>
  );
}
