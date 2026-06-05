import { AnalysisBadge, AnalysisEmptyState } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { TrafficTimelineEvent } from "./trafficTimelineEvents";

interface TrafficTimelineTrackProps {
  events: TrafficTimelineEvent[];
  hoveredLabel: string | null;
  lockedLabel: string | null;
  onHoverEvent?: (label: string | null) => void;
  onSelectEvent?: (label: string) => void;
}

const badgeToneByKind = {
  peak: "amber",
  burst: "blue",
} as const;

export function TrafficTimelineTrack({
  events,
  hoveredLabel,
  lockedLabel,
  onHoverEvent,
  onSelectEvent,
}: TrafficTimelineTrackProps) {
  if (events.length === 0) {
    return <AnalysisEmptyState className="px-0 py-4 text-left">当前时间线未生成可标记事件</AnalysisEmptyState>;
  }

  return (
    <div className="meow-soft-fill flex flex-wrap gap-2 border border-[var(--meow-tile-divider)] px-3 py-3">
      {events.map((event) => {
        const isHovered = hoveredLabel === event.label;
        const isLocked = lockedLabel === event.label;
        return (
          <button
            key={`${event.kind}-${event.label}`}
            type="button"
            data-testid={`timeline-event-marker-${event.kind}-${event.label}`}
            onMouseEnter={() => onHoverEvent?.(event.label)}
            onMouseLeave={() => onHoverEvent?.(null)}
            onClick={() => onSelectEvent?.(event.label)}
            className={cn(
              "group meow-tile flex min-w-[164px] flex-1 items-start gap-2 px-3 py-2 text-left transition-all",
              isLocked
                ? "border-cyan-300 bg-cyan-50/80 shadow-[inset_0_0_0_1px_rgba(14,116,144,0.22)]"
                : isHovered
                  ? "border-amber-200 bg-amber-50/75"
                  : "border-[var(--meow-tile-divider)] bg-white/70 hover:border-slate-300 hover:bg-white/90",
            )}
          >
            <span
              className={cn(
                "mt-1 h-2.5 w-2.5 shrink-0 rounded-full",
                event.kind === "peak" ? "bg-amber-500" : "bg-sky-500",
                event.severity === "high" ? "ring-2 ring-amber-200" : "",
              )}
            />
            <span className="min-w-0 flex-1">
              <span className="mb-1 flex items-center gap-2">
                <AnalysisBadge tone={badgeToneByKind[event.kind]}>{event.title}</AnalysisBadge>
                <span className="font-mono text-[11px] text-slate-400">{event.label}</span>
              </span>
              <span className="block text-xs font-semibold text-slate-700">{event.count} pkt</span>
              <span className="mt-0.5 block text-[11px] leading-5 text-slate-500">{event.detail}</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
