import { useMemo } from "react";
import { AnalysisWorkbenchShell } from "../../components/analysis/AnalysisWorkbenchShell";
import type { AnalysisWorkbenchSection } from "../../components/analysis/analysisWorkbenchTypes";
import { normalizeTrafficTimelineBuckets } from "./trafficTimeline";
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

const trafficWorkbenchSections: AnalysisWorkbenchSection[] = trafficSectionGroups.flatMap((group) =>
  group.items.map((item) => ({
    id: item.id,
    title: item.title,
    description: item.description,
    group: group.label,
  })),
);

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
    [
      props.topComputerNames,
      props.topDestPorts,
      props.topDomains,
      props.topDstIPs,
      props.topSrcIPs,
      props.topSrcPorts,
      props.topTalkers,
    ],
  );
  const selectedSectionMeta = useMemo(
    () => trafficSectionGroups.flatMap((group) => group.items).find((item) => item.id === props.selectedSection),
    [props.selectedSection],
  );
  const hasTimelineSelection = Boolean(
    props.timelineSelection.hoveredLabel ||
    props.timelineSelection.lockedLabel ||
    props.timelineSelection.selectedRange,
  );
  const linkedContextLabel = props.timelineSelection.selectedRange
    ? `${props.timelineSelection.selectedRange.startLabel} ~ ${props.timelineSelection.selectedRange.endLabel}`
    : (props.timelineSelection.lockedLabel ?? props.timelineSelection.hoveredLabel);

  return (
    <AnalysisWorkbenchShell
      sections={trafficWorkbenchSections}
      selectedSection={props.selectedSection}
      onSectionChange={props.onSelectSection}
      title={selectedSectionMeta?.title}
      description={selectedSectionMeta?.description}
      contentClassName="p-0"
    >
      <TrafficGraphSelectedPanel
        {...props}
        conversationBuckets={conversationBuckets}
        hasTimelineSelection={hasTimelineSelection}
        linkedContextLabel={linkedContextLabel}
        talkerPanels={talkerPanels}
        timelinePoints={timelinePoints}
        topologyEdges={topologyEdges}
      />
    </AnalysisWorkbenchShell>
  );
}
