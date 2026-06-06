import { normalizeTrafficTimelineBuckets } from "./trafficTimeline";
import { TrafficConversationsPanel } from "./TrafficConversationsPanel";
import { TrafficOverviewNotes } from "./TrafficOverviewNotes";
import { TrafficProtocolsPanel } from "./TrafficProtocolsPanel";
import { TrafficTalkersPanel } from "./TrafficTalkersPanel";
import { TrafficTopologyPanel } from "./TrafficTopologyPanel";
import { TrafficTrendPanel } from "./TrafficTrendPanel";
import { buildConversationBuckets, buildTalkerPanels, buildTopologyEdges } from "./trafficGraphPanelModel";
import type { TrafficGraphPanelsProps } from "./trafficGraphPanelTypes";

export function TrafficGraphSelectedPanel({
  conversationBuckets,
  hasTimelineSelection,
  linkedContextLabel,
  talkerPanels,
  timelinePoints,
  topologyEdges,
  ...props
}: TrafficGraphPanelsProps & {
  conversationBuckets: ReturnType<typeof buildConversationBuckets>;
  hasTimelineSelection: boolean;
  linkedContextLabel: string | null | undefined;
  talkerPanels: ReturnType<typeof buildTalkerPanels>;
  timelinePoints: ReturnType<typeof normalizeTrafficTimelineBuckets>;
  topologyEdges: ReturnType<typeof buildTopologyEdges>;
}) {
  switch (props.selectedSection) {
    case "trend":
      return (
        <TrafficTrendPanel
          evidenceError={props.evidenceError ?? null}
          evidenceLoading={props.evidenceLoading ?? false}
          evidenceRecords={props.evidenceRecords ?? []}
          timelinePoints={timelinePoints}
          timelineSelection={props.timelineSelection}
          onTimelineClearSelection={props.onTimelineClearSelection}
          onTimelineHoverLabel={props.onTimelineHoverLabel}
          onTimelineLockedLabel={props.onTimelineLockedLabel}
          onTimelineRangeSelect={props.onTimelineRangeSelect}
        />
      );
    case "topology":
      return <TrafficTopologyPanel hasTimelineSelection={hasTimelineSelection} linkedContextLabel={linkedContextLabel} topologyEdges={topologyEdges} />;
    case "protocols":
      return <TrafficProtocolsPanel hasTimelineSelection={hasTimelineSelection} protocolDist={props.protocolDist} protocolHierarchy={props.protocolHierarchy} onJumpFilter={props.onJumpFilter} />;
    case "conversations":
      return <TrafficConversationsPanel hasTimelineSelection={hasTimelineSelection} buckets={conversationBuckets} />;
    case "talkers":
      return <TrafficTalkersPanel hasTimelineSelection={hasTimelineSelection} panels={talkerPanels} onJumpFilter={props.onJumpFilter} />;
    case "overview":
    default:
      return <TrafficOverviewNotes />;
  }
}
