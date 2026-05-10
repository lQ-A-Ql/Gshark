import { useCallback, type MutableRefObject } from "react";

interface UseScheduledPacketPageLoadOptions {
  readonly loadMoreScheduledRef: MutableRefObject<number | null>;
  readonly pageStartRef: MutableRefObject<number>;
  readonly loadPacketPage: (cursor: number) => Promise<unknown>;
}

export function useScheduledPacketPageLoad({
  loadMoreScheduledRef,
  pageStartRef,
  loadPacketPage,
}: UseScheduledPacketPageLoadOptions) {
  return useCallback(
    (delayMs = 120) => {
      if (loadMoreScheduledRef.current != null) return;
      loadMoreScheduledRef.current = window.setTimeout(() => {
        loadMoreScheduledRef.current = null;
        void loadPacketPage(pageStartRef.current);
      }, delayMs);
    },
    [loadMoreScheduledRef, loadPacketPage, pageStartRef],
  );
}
