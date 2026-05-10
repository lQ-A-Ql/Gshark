import type { MutableRefObject } from "react";

export function clearWindowTimer(timerRef: MutableRefObject<number | null>) {
  if (timerRef.current == null) return;
  window.clearTimeout(timerRef.current);
  timerRef.current = null;
}
