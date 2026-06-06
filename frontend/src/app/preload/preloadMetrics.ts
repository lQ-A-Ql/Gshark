import type { PreloadTelemetry } from "./preloadTelemetry";

export type PreloadMetricsSummary = {
  started: number;
  fulfilled: number;
  reused: number;
  skipped: number;
  aborted: number;
  failed: number;
  promoted: number;
  hitRate: number;
  abortFailRate: number;
  wasteRate: number;
};

export function createPreloadMetricsRecorder() {
  const events: PreloadTelemetry[] = [];
  return {
    record(event: PreloadTelemetry) {
      events.push(event);
    },
    summary(targetId?: string): PreloadMetricsSummary {
      return summarizePreloadEvents(targetId ? events.filter((event) => event.targetId === targetId) : events);
    },
    clear() {
      events.splice(0);
    },
  };
}

export function summarizePreloadEvents(events: PreloadTelemetry[]): PreloadMetricsSummary {
  const count = (name: PreloadTelemetry["event"]) => events.filter((event) => event.event === name).length;
  const started = count("preload.started");
  const fulfilled = count("preload.fulfilled");
  const reused = count("preload.reused") + count("preload.promoted");
  const skipped = count("preload.skipped");
  const aborted = count("preload.aborted");
  const failed = count("preload.failed");
  const promoted = count("preload.promoted");
  const completed = fulfilled + reused + aborted + failed;
  return {
    started,
    fulfilled,
    reused,
    skipped,
    aborted,
    failed,
    promoted,
    hitRate: ratio(reused, fulfilled + reused),
    abortFailRate: ratio(aborted + failed, completed),
    wasteRate: ratio(skipped + aborted, events.length),
  };
}

export function shouldDowngradePreload(summary: PreloadMetricsSummary, threshold = 0.35): "heavy-off" | "light-off" | "none" {
  if (summary.abortFailRate >= threshold) return "heavy-off";
  if (summary.wasteRate >= threshold) return "light-off";
  return "none";
}

function ratio(numerator: number, denominator: number) {
  if (denominator <= 0) return 0;
  return Number((numerator / denominator).toFixed(4));
}
