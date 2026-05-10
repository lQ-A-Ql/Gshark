import { useCallback, useState } from "react";
import type { RecentCapture } from "../../core/types";
import { readRecentCaptures, updateRecentCaptures, writeRecentCaptures } from "../recentCaptures";

export function useRecentCapturesState() {
  const [recentCaptures, setRecentCaptures] = useState<RecentCapture[]>(() => readRecentCaptures());

  const rememberRecentCapture = useCallback((entry: RecentCapture) => {
    setRecentCaptures((prev) => {
      const next = updateRecentCaptures(prev, entry);
      writeRecentCaptures(next);
      return next;
    });
  }, []);

  return { recentCaptures, rememberRecentCapture };
}
