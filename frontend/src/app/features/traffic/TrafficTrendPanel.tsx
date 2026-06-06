import { StatusHint } from "../../components/DesignSystem";
import { AnalysisPanel } from "../../components/analysis/AnalysisPrimitives";
import type { UnifiedEvidenceRecord } from "../../core/evidenceTypes";
import { TrafficAreaChart } from "./TrafficAreaChart";
import { TrafficTimelineEvidenceTrack } from "./TrafficTimelineEvidenceTrack";
import { TrafficTimelineSummary } from "./TrafficTimelineSummary";
import { TrafficTimelineTrack } from "./TrafficTimelineTrack";
import { buildTrafficTimelineEvidence } from "./trafficTimelineEvidence";
import { buildTrafficTimelineEvents } from "./trafficTimelineEvents";
import type { TrafficTimelineRangeSelection, TrafficTimelineSelection } from "./trafficTimeline";
import type { AnalysisBucket } from "./trafficGraphPanelTypes";

export function TrafficTrendPanel({
  evidenceError,
  evidenceLoading,
  evidenceRecords,
  timelinePoints,
  timelineSelection,
  onTimelineClearSelection,
  onTimelineHoverLabel,
  onTimelineLockedLabel,
  onTimelineRangeSelect,
}: {
  evidenceError: string | null;
  evidenceLoading: boolean;
  evidenceRecords: UnifiedEvidenceRecord[];
  timelinePoints: AnalysisBucket[];
  timelineSelection: TrafficTimelineSelection;
  onTimelineClearSelection: () => void;
  onTimelineHoverLabel: (label: string | null) => void;
  onTimelineLockedLabel: (label: string | null) => void;
  onTimelineRangeSelect: (range: TrafficTimelineRangeSelection | null) => void;
}) {
  const timelineEvents = buildTrafficTimelineEvents(timelinePoints);
  const timelineEvidence = buildTrafficTimelineEvidence(timelinePoints, evidenceRecords);
  return (
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
          onSelectPoint={(point) => onTimelineLockedLabel(point.label === timelineSelection.lockedLabel ? null : point.label)}
          onSelectRange={onTimelineRangeSelect}
        />
        <TrafficTimelineTrack
          events={timelineEvents}
          hoveredLabel={timelineSelection.hoveredLabel}
          lockedLabel={timelineSelection.lockedLabel}
          onHoverEvent={onTimelineHoverLabel}
          onSelectEvent={(label) => onTimelineLockedLabel(label === timelineSelection.lockedLabel ? null : label)}
        />
        <TrafficEvidenceTrack
          evidenceError={evidenceError}
          evidenceLoading={evidenceLoading}
          timelineEvidence={timelineEvidence}
          timelineSelection={timelineSelection}
          onTimelineHoverLabel={onTimelineHoverLabel}
          onTimelineLockedLabel={onTimelineLockedLabel}
        />
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
}

function TrafficEvidenceTrack({
  evidenceError,
  evidenceLoading,
  timelineEvidence,
  timelineSelection,
  onTimelineHoverLabel,
  onTimelineLockedLabel,
}: {
  evidenceError: string | null;
  evidenceLoading: boolean;
  timelineEvidence: ReturnType<typeof buildTrafficTimelineEvidence>;
  timelineSelection: TrafficTimelineSelection;
  onTimelineHoverLabel: (label: string | null) => void;
  onTimelineLockedLabel: (label: string | null) => void;
}) {
  if (evidenceLoading) return <StatusHint tone="blue" className="text-xs">正在加载 Evidence / YARA 证据...</StatusHint>;
  if (evidenceError) return <StatusHint tone="amber" className="text-xs">Evidence 加载失败，流量时间线仍可用：{evidenceError}</StatusHint>;
  return (
    <TrafficTimelineEvidenceTrack
      events={timelineEvidence.events}
      hoveredLabel={timelineSelection.hoveredLabel}
      lockedLabel={timelineSelection.lockedLabel}
      onHoverEvent={onTimelineHoverLabel}
      onSelectEvent={(label) => onTimelineLockedLabel(label === timelineSelection.lockedLabel ? null : label)}
    />
  );
}
