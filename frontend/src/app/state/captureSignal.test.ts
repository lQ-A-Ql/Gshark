import { describe, expect, it, vi } from "vitest";
import { waitForCaptureSignal, wakeCaptureWaiters } from "./captureSignal";

describe("captureSignal helpers", () => {
  it("resolves waiters when capture signals wake", async () => {
    vi.useFakeTimers();
    const waiters = new Set<() => void>();
    const resolved = vi.fn();
    void waitForCaptureSignal(waiters, 1000).then(resolved);

    expect(waiters.size).toBe(1);
    wakeCaptureWaiters(waiters);
    await vi.runAllTimersAsync();

    expect(waiters.size).toBe(0);
    expect(resolved).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });

  it("resolves waiters on timeout and removes the waiter", async () => {
    vi.useFakeTimers();
    const waiters = new Set<() => void>();
    const resolved = vi.fn();
    void waitForCaptureSignal(waiters, 1000).then(resolved);

    await vi.advanceTimersByTimeAsync(1000);

    expect(waiters.size).toBe(0);
    expect(resolved).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });
});
