import type { TrafficBucket } from "../../core/types";

export type TrafficTimelineEventKind = "peak" | "burst";
export type TrafficTimelineEventSeverity = "high" | "medium";

export interface TrafficTimelineEvent {
  kind: TrafficTimelineEventKind;
  label: string;
  count: number;
  severity: TrafficTimelineEventSeverity;
  title: string;
  detail: string;
}

function isValidBucket(bucket: TrafficBucket): bucket is TrafficBucket {
  return typeof bucket.label === "string" && bucket.label.trim().length > 0 && Number.isFinite(bucket.count);
}

function buildPeakEvents(points: TrafficBucket[]): TrafficTimelineEvent[] {
  const sorted = [...points].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)).slice(0, 5);

  return sorted.map((point, index) => ({
    kind: "peak",
    label: point.label,
    count: point.count,
    severity: index === 0 ? "high" : "medium",
    title: index === 0 ? "主峰值" : "峰值点",
    detail: `${point.label} 出现 ${point.count} 个数据包`,
  }));
}

function buildBurstEvents(points: TrafficBucket[]): TrafficTimelineEvent[] {
  const events: TrafficTimelineEvent[] = [];

  for (let index = 1; index < points.length; index += 1) {
    const current = points[index];
    const previousWindow = points.slice(Math.max(0, index - 5), index);
    if (previousWindow.length === 0) {
      continue;
    }

    const baseline = previousWindow.reduce((sum, point) => sum + point.count, 0) / previousWindow.length;
    if (baseline <= 0) {
      continue;
    }

    if (current.count >= baseline * 3 && current.count >= 10) {
      events.push({
        kind: "burst",
        label: current.label,
        count: current.count,
        severity: "medium",
        title: "突增点",
        detail: `${current.label} 相比前序均值 ${baseline.toFixed(1)}x 出现显著突增`,
      });
    }
  }

  return events.slice(0, 5);
}

export function buildTrafficTimelineEvents(input: TrafficBucket[]): TrafficTimelineEvent[] {
  if (!Array.isArray(input) || input.length === 0) {
    return [];
  }

  const points = input
    .filter(isValidBucket)
    .map((bucket) => ({ label: bucket.label.trim(), count: Number(bucket.count) }))
    .filter((bucket) => bucket.label.length > 0 && Number.isFinite(bucket.count) && bucket.count > 0);

  if (points.length === 0) {
    return [];
  }

  const peakEvents = buildPeakEvents(points);
  const burstEvents = buildBurstEvents(points);

  return [...peakEvents, ...burstEvents].sort((a, b) => a.label.localeCompare(b.label) || a.kind.localeCompare(b.kind));
}
