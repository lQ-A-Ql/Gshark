import { act, renderHook } from "@testing-library/react";
import { useRef } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useScheduledPacketPageLoad } from "./useScheduledPacketPageLoad";

describe("useScheduledPacketPageLoad", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("deduplicates pending timers and loads the current page start", () => {
    const loadPacketPage = vi.fn(async () => undefined);
    const { result } = renderHook(() => {
      const loadMoreScheduledRef = useRef<number | null>(null);
      const pageStartRef = useRef(40);
      const scheduleLoadMore = useScheduledPacketPageLoad({
        loadMoreScheduledRef,
        pageStartRef,
        loadPacketPage,
      });
      return { loadMoreScheduledRef, pageStartRef, scheduleLoadMore };
    });

    act(() => {
      result.current.scheduleLoadMore(50);
      result.current.pageStartRef.current = 80;
      result.current.scheduleLoadMore(50);
      vi.advanceTimersByTime(50);
    });

    expect(loadPacketPage).toHaveBeenCalledTimes(1);
    expect(loadPacketPage).toHaveBeenCalledWith(80);
    expect(result.current.loadMoreScheduledRef.current).toBeNull();
  });
});
