import { AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import type { TrafficProtocolTreeNode } from "../../core/types";
import { SimpleBarChart } from "./TrafficSimpleBarChart";
import { TrafficProtocolTree } from "./TrafficProtocolTree";
import { filterForProtocolBucket } from "./trafficGraphFilters";
import type { AnalysisBucket } from "./trafficGraphPanelTypes";
import { TrafficSelectionWarning } from "./trafficSelectionWarning";

export function TrafficProtocolsPanel({
  hasTimelineSelection,
  protocolDist,
  protocolHierarchy,
  onJumpFilter,
}: {
  hasTimelineSelection: boolean;
  protocolDist: AnalysisBucket[];
  protocolHierarchy?: TrafficProtocolTreeNode[];
  onJumpFilter: (filter: string) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
      <AnalysisPanel title="协议分布" tone="amber">
        <TrafficSelectionWarning show={hasTimelineSelection} />
        <SimpleBarChart data={protocolDist} color="bg-emerald-500" onSelect={(row) => onJumpFilter(filterForProtocolBucket(row.label) ?? "")} />
      </AnalysisPanel>
      <AnalysisPanel title="协议层级树" tone="amber">
        <TrafficSelectionWarning show={hasTimelineSelection} />
        <TrafficProtocolTree data={protocolHierarchy ?? []} />
      </AnalysisPanel>
    </div>
  );
}
