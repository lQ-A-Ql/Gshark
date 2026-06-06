import { AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import { SimpleBarChart } from "./TrafficSimpleBarChart";
import type { AnalysisBucket } from "./trafficGraphPanelTypes";
import { TrafficSelectionWarning } from "./trafficSelectionWarning";

export function TrafficConversationsPanel({
  buckets,
  hasTimelineSelection,
}: {
  buckets: AnalysisBucket[];
  hasTimelineSelection: boolean;
}) {
  return (
    <AnalysisPanel title="会话排行" tone="amber">
      <TrafficSelectionWarning show={hasTimelineSelection} />
      <SimpleBarChart data={buckets} color="bg-amber-500" />
    </AnalysisPanel>
  );
}
