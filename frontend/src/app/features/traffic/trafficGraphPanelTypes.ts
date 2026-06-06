import type { TrafficBucket, TrafficConversation, TrafficProtocolTreeNode } from "../../core/types";
import type { UnifiedEvidenceRecord } from "../../core/evidenceTypes";
import type { TrafficTimelineRangeSelection, TrafficTimelineSelection } from "./trafficTimeline";

export type AnalysisBucket = TrafficBucket;
export type TrafficGraphSection = "overview" | "trend" | "topology" | "protocols" | "conversations" | "talkers";

export type TrafficGraphPanelsProps = {
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
