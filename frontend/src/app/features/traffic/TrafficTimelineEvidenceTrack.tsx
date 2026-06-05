import { AnalysisBadge, AnalysisEmptyState } from "../../components/analysis/AnalysisPrimitives";
import { cn } from "../../components/ui/utils";
import type { TrafficTimelineEvidenceEvent } from "./trafficTimelineEvidence";

interface TrafficTimelineEvidenceTrackProps {
  events: TrafficTimelineEvidenceEvent[];
  hoveredLabel: string | null;
  lockedLabel: string | null;
  onHoverEvent?: (label: string | null) => void;
  onSelectEvent?: (label: string) => void;
}

function severityClass(severity: TrafficTimelineEvidenceEvent["severity"]) {
  switch (severity) {
    case "critical":
      return "bg-red-600 ring-red-200";
    case "high":
      return "bg-rose-500 ring-rose-200";
    case "medium":
      return "bg-amber-500 ring-amber-200";
    case "low":
      return "bg-sky-500 ring-sky-200";
    default:
      return "bg-slate-400 ring-slate-200";
  }
}

export function TrafficTimelineEvidenceTrack({
  events,
  hoveredLabel,
  lockedLabel,
  onHoverEvent,
  onSelectEvent,
}: TrafficTimelineEvidenceTrackProps) {
  if (events.length === 0) {
    return <AnalysisEmptyState className="px-0 py-4 text-left">当前时间窗口未定位到 Evidence / YARA 事件</AnalysisEmptyState>;
  }

  return (
    <div className="meow-soft-fill border border-[var(--meow-tile-divider)] px-3 py-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">Evidence / YARA Track</div>
        <div className="text-[11px] text-slate-500">{events.length} positioned events</div>
      </div>
      <div className="flex flex-wrap gap-2">
        {events.slice(0, 24).map((event) => {
          const isHovered = hoveredLabel === event.label;
          const isLocked = lockedLabel === event.label;
          return (
            <button
              key={event.id}
              type="button"
              data-testid={`timeline-evidence-marker-${event.id}`}
              onMouseEnter={() => onHoverEvent?.(event.label)}
              onMouseLeave={() => onHoverEvent?.(null)}
              onClick={() => onSelectEvent?.(event.label)}
              className={cn(
                "meow-tile flex min-w-[190px] flex-1 items-start gap-2 px-3 py-2 text-left transition-all",
                isLocked
                  ? "border-cyan-300 bg-cyan-50/80 shadow-[inset_0_0_0_1px_rgba(14,116,144,0.22)]"
                  : isHovered
                    ? "border-amber-200 bg-amber-50/75"
                    : "border-[var(--meow-tile-divider)] bg-white/70 hover:border-slate-300 hover:bg-white/90",
              )}
            >
              <span className={cn("mt-1 h-3 w-3 shrink-0 rounded-sm ring-2", severityClass(event.severity))} />
              <span className="min-w-0 flex-1">
                <span className="mb-1 flex flex-wrap items-center gap-2">
                  <AnalysisBadge tone={event.isYara ? "blue" : "slate"}>{event.isYara ? "YARA" : event.module}</AnalysisBadge>
                  {event.isCommunityYara ? <AnalysisBadge tone="amber">COMMUNITY</AnalysisBadge> : null}
                  <span className="font-mono text-[11px] text-slate-400">{event.label}</span>
                </span>
                <span className="block truncate text-xs font-semibold text-slate-700">{event.title}</span>
                <span className="mt-0.5 block text-[11px] leading-5 text-slate-500">
                  {event.sourceType || "evidence"}
                  {event.packetId ? ` · packet #${event.packetId}` : ""}
                </span>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
