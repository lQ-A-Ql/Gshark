import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useCaptureSignalWaiters } from "./useCaptureSignalWaiters";

describe("useCaptureSignalWaiters", () => {
  it("keeps capture waiter refs stable and wakes pending waiters", async () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useCaptureSignalWaiters());
    const resolved = vi.fn();

    void result.current.waitForCaptureSignal(1000).then(resolved);
    expect(result.current.captureWaitersRef.current.size).toBe(1);

    act(() => {
      result.current.wakeCaptureWaiters();
    });
    await vi.runAllTimersAsync();

    expect(result.current.captureWaitersRef.current.size).toBe(0);
    expect(resolved).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });
});
