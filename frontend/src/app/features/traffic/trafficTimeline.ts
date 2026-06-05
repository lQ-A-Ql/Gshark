import type { TrafficBucket } from "../../core/types";

export interface TrafficTimelineRangeSelection {
  startLabel: string;
  endLabel: string;
}

export interface TrafficTimelineSelection {
  hoveredLabel: string | null;
  lockedLabel: string | null;
  selectedRange: TrafficTimelineRangeSelection | null;
}

interface NormalizedTimelinePoint {
  label: string;
  sortKey: number;
  count: number;
}

function normalizeClockLabel(input: string): { label: string; sortKey: number } | null {
  const match = input.match(/^(\d{1,2}):(\d{2}):(\d{2})(?:[.,]\d+)?$/);
  if (!match) return null;

  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  const seconds = Number(match[3]);
  if (hours > 23 || minutes > 59 || seconds > 59) return null;

  return {
    label: [hours, minutes, seconds].map((value) => String(value).padStart(2, "0")).join(":"),
    sortKey: hours * 3600 + minutes * 60 + seconds,
  };
}

function normalizeEpochLabel(input: string): { label: string; sortKey: number } | null {
  if (!/^\d+(?:\.\d+)?$/.test(input)) return null;

  const numericValue = Number(input);
  if (!Number.isFinite(numericValue)) return null;

  const milliseconds = numericValue > 1e12 ? numericValue : numericValue > 1e9 ? numericValue * 1000 : NaN;
  if (!Number.isFinite(milliseconds)) return null;

  const date = new Date(milliseconds);
  const time = date.getTime();
  if (Number.isNaN(time)) return null;

  return {
    label: date.toISOString().slice(11, 19),
    sortKey: Math.floor(time / 1000),
  };
}

function normalizeDateLabel(input: string): { label: string; sortKey: number } | null {
  const parsed = Date.parse(input);
  if (Number.isNaN(parsed)) return null;

  const date = new Date(parsed);
  return {
    label: date.toISOString().slice(11, 19),
    sortKey: Math.floor(parsed / 1000),
  };
}

export function normalizeTimelineLabel(input: string): { label: string; sortKey: number } | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  return normalizeClockLabel(trimmed) ?? normalizeEpochLabel(trimmed) ?? normalizeDateLabel(trimmed);
}

export function normalizeTrafficTimelineBuckets(buckets: TrafficBucket[]): TrafficBucket[] {
  const aggregated = new Map<string, NormalizedTimelinePoint>();

  for (const bucket of buckets) {
    const normalized = normalizeTimelineLabel(String(bucket.label ?? ""));
    const count = Number(bucket.count ?? 0);
    if (!normalized || !Number.isFinite(count) || count <= 0) continue;

    const existing = aggregated.get(normalized.label);
    if (existing) {
      existing.count += count;
      existing.sortKey = Math.min(existing.sortKey, normalized.sortKey);
      continue;
    }

    aggregated.set(normalized.label, {
      label: normalized.label,
      sortKey: normalized.sortKey,
      count,
    });
  }

  return Array.from(aggregated.values())
    .sort((a, b) => a.sortKey - b.sortKey || a.label.localeCompare(b.label))
    .map(({ label, count }) => ({ label, count }));
}

export function buildTimelineBucketsFromPacketTimes(packetTimes: string[]): TrafficBucket[] {
  const buckets = new Map<string, TrafficBucket>();

  for (const packetTime of packetTimes) {
    const normalized = normalizeTimelineLabel(packetTime);
    if (!normalized) continue;

    const current = buckets.get(normalized.label);
    if (current) {
      current.count += 1;
      continue;
    }

    buckets.set(normalized.label, { label: normalized.label, count: 1 });
  }

  return normalizeTrafficTimelineBuckets(Array.from(buckets.values()));
}
