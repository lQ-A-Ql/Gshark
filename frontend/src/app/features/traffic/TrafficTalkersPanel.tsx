import { AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import { SimpleBarChart } from "./TrafficSimpleBarChart";
import type { buildTalkerPanels } from "./trafficGraphPanelModel";
import { TrafficSelectionWarning } from "./trafficSelectionWarning";

export function TrafficTalkersPanel({
  hasTimelineSelection,
  panels,
  onJumpFilter,
}: {
  hasTimelineSelection: boolean;
  panels: ReturnType<typeof buildTalkerPanels>;
  onJumpFilter: (filter: string) => void;
}) {
  return (
    <div className="grid grid-cols-1 gap-0 xl:grid-cols-2">
      {panels.map((panel) => (
        <AnalysisPanel key={panel.title} title={panel.title} tone="amber">
          <TrafficSelectionWarning show={hasTimelineSelection} />
          <SimpleBarChart data={panel.data} color={panel.color} onSelect={panel.onSelect ? (row) => onJumpFilter(panel.onSelect?.(row.label) ?? "") : undefined} />
        </AnalysisPanel>
      ))}
    </div>
  );
}
