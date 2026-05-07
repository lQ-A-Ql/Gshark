import type { RecentCapture } from "../core/types";

export const RECENT_CAPTURES_STORAGE_KEY = "gshark.recent-captures.v1";
export const MAX_RECENT_CAPTURES = 8;

export function readRecentCaptures(): RecentCapture[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RECENT_CAPTURES_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((item) => ({
        path: String(item?.path ?? "").trim(),
        name: String(item?.name ?? "").trim(),
        sizeBytes: Number(item?.sizeBytes ?? 0),
        lastOpenedAt: String(item?.lastOpenedAt ?? "").trim(),
      }))
      .filter((item) => item.path)
      .slice(0, MAX_RECENT_CAPTURES);
  } catch {
    return [];
  }
}

export function writeRecentCaptures(items: RecentCapture[]) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(RECENT_CAPTURES_STORAGE_KEY, JSON.stringify(items.slice(0, MAX_RECENT_CAPTURES)));
  } catch {
    // ignore persistence failures
  }
}
