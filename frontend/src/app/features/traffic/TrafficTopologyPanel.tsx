import { AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import { TrafficTopologyGraph, type TopologyEdge } from "./TrafficTopologyGraph";
import { TrafficSelectionWarning } from "./trafficSelectionWarning";

export function TrafficTopologyPanel({
  hasTimelineSelection,
  linkedContextLabel,
  topologyEdges,
}: {
  hasTimelineSelection: boolean;
  linkedContextLabel: string | null | undefined;
  topologyEdges: TopologyEdge[];
}) {
  return (
    <AnalysisPanel title="会话拓扑 (源 → 目标)" tone="amber">
      <TrafficSelectionWarning show={hasTimelineSelection} />
      <TrafficTopologyGraph edges={topologyEdges} maxNodes={16} height={360} linkedContextLabel={linkedContextLabel} />
    </AnalysisPanel>
  );
}
