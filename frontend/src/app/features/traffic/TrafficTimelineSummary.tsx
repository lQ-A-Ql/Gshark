import { AnalysisCallout, AnalysisMiniStat } from "../../components/analysis/AnalysisPrimitives";
import type { TimelinePoint } from "./TrafficAreaChart";
import type { TrafficTimelineSelection } from "./trafficTimeline";
import type { TrafficTimelineEvidenceEvent } from "./trafficTimelineEvidence";

interface TrafficTimelineSummaryProps {
  selection: TrafficTimelineSelection;
  points: TimelinePoint[];
  evidenceEvents?: TrafficTimelineEvidenceEvent[];
  unplacedEvidenceCount?: number;
  onClearSelection: () => void;
}

function findPoint(points: TimelinePoint[], label: string | null): TimelinePoint | null {
  if (!label) {
    return null;
  }
  return points.find((point) => point.label === label) ?? null;
}

export function TrafficTimelineSummary({
  selection,
  points,
  evidenceEvents = [],
  unplacedEvidenceCount = 0,
  onClearSelection,
}: TrafficTimelineSummaryProps) {
  const hoveredPoint = findPoint(points, selection.hoveredLabel);
  const lockedPoint = findPoint(points, selection.lockedLabel);
  const selectedRange = selection.selectedRange;
  const hasSelection = Boolean(selection.hoveredLabel || selection.lockedLabel || selection.selectedRange);
  const activeLabel = selectedRange ? null : (selection.lockedLabel ?? selection.hoveredLabel);
  const activeEvidence = activeLabel ? evidenceEvents.filter((event) => event.label === activeLabel) : [];
  const yaraCount = evidenceEvents.filter((event) => event.isYara).length;
  const communityYaraCount = evidenceEvents.filter((event) => event.isCommunityYara).length;

  let headline = "悬停或点击时间点以查看细节，也可拖拽选择时间窗口。";
  if (selectedRange) {
    headline = `已选择时间窗口 ${selectedRange.startLabel} ~ ${selectedRange.endLabel}，当前其他卡片仍展示全局统计。`;
  } else if (lockedPoint) {
    headline = `已锁定 ${lockedPoint.label}，该秒共有 ${lockedPoint.count} 个数据包。`;
  } else if (hoveredPoint) {
    headline = `正在查看 ${hoveredPoint.label}，该秒共有 ${hoveredPoint.count} 个数据包。`;
  }

  return (
    <div className="meow-tile border-[var(--meow-tile-divider)] bg-white/80 p-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">Timeline Summary</div>
          <div className="mt-1 text-sm font-semibold text-slate-800">{headline}</div>
        </div>
        <button
          type="button"
          onClick={onClearSelection}
          disabled={!hasSelection}
          className="rounded-sm border border-[var(--meow-tile-divider)] bg-white px-3 py-1 text-xs font-semibold text-slate-600 transition-all hover:border-slate-300 hover:text-slate-800 disabled:cursor-not-allowed disabled:opacity-45"
        >
          清除选择
        </button>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-3">
        <AnalysisMiniStat title="悬停时间点" value={hoveredPoint ? `${hoveredPoint.label} · ${hoveredPoint.count} pkt` : "未悬停"} tone="amber" />
        <AnalysisMiniStat title="锁定时间点" value={lockedPoint ? `${lockedPoint.label} · ${lockedPoint.count} pkt` : "未锁定"} tone="blue" />
        <AnalysisMiniStat
          title="时间窗口"
          value={selectedRange ? `${selectedRange.startLabel} ~ ${selectedRange.endLabel}` : "未选择"}
          tone="slate"
        />
        <AnalysisMiniStat title="Evidence" value={`${evidenceEvents.length} positioned / ${unplacedEvidenceCount} unplaced`} tone="slate" />
        <AnalysisMiniStat title="YARA" value={`${yaraCount} hits`} tone="blue" />
        <AnalysisMiniStat title="Community YARA" value={`${communityYaraCount} hits`} tone="amber" />
      </div>

      {activeEvidence.length > 0 ? (
        <div className="mt-3 rounded-sm border border-[var(--meow-tile-divider)] bg-white/70 p-3">
          <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">当前时间点证据</div>
          <div className="mt-2 space-y-1">
            {activeEvidence.slice(0, 4).map((event) => (
              <div key={event.id} className="text-xs text-slate-600">
                <span className="font-semibold text-slate-800">{event.isCommunityYara ? "COMMUNITY YARA" : event.isYara ? "YARA" : event.module}</span>
                {" · "}
                {event.title}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {selectedRange ? (
        <AnalysisCallout tone="amber" className="mt-3">
          已选择时间窗口/时间点；当前卡片仍展示全局统计，窗口统计待接入。
        </AnalysisCallout>
      ) : null}
    </div>
  );
}
