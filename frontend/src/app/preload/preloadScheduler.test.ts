import { afterEach, describe, expect, it, vi } from "vitest";
import { schedulePreload, resetPreloadSchedulerForTest, setPreloadFeatureFlagOverrideForTest, cancelCapturePreloads } from "./preloadScheduler";
import { setPreloadTelemetrySinkForTest } from "./preloadTelemetry";

describe("preload scheduler", () => {
  afterEach(() => {
    vi.useRealTimers();
    resetPreloadSchedulerForTest();
    setPreloadTelemetrySinkForTest(undefined);
  });

  it("limits light-data concurrency to two", async () => {
    const releases: Array<() => void> = [];
    let active = 0;
    let maxActive = 0;
    setPreloadFeatureFlagOverrideForTest(() => true);

    const jobs = Array.from({ length: 5 }, (_, index) =>
      schedulePreload("light:/traffic-graph", "route-enter", {
        cacheKey: `k-${index}`,
        run: () =>
          new Promise((resolve) => {
            active += 1;
            maxActive = Math.max(maxActive, active);
            releases.push(() => {
              active -= 1;
              resolve(undefined);
            });
          }),
      }),
    );

    await vi.waitFor(() => expect(releases).toHaveLength(2));
    while (releases.length > 0) {
      releases.shift()?.();
      await Promise.resolve();
    }
    await Promise.all(jobs);

    expect(maxActive).toBeLessThanOrEqual(2);
  });

  it("dedupes same target and cache key", async () => {
    setPreloadFeatureFlagOverrideForTest(() => true);
    const run = vi.fn(async () => undefined);

    await Promise.all([
      schedulePreload("light:/traffic-graph", "route-enter", { cacheKey: "same", run }),
      schedulePreload("light:/traffic-graph", "route-enter", { cacheKey: "same", run }),
    ]);

    expect(run).toHaveBeenCalledTimes(1);
  });

  it("aborts timed-out work and reports aborted telemetry", async () => {
    vi.useFakeTimers();
    setPreloadFeatureFlagOverrideForTest(() => true);
    const events: string[] = [];
    setPreloadTelemetrySinkForTest((event) => events.push(event.event));
    const job = schedulePreload("light:/traffic-graph", "route-enter", {
      cacheKey: "timeout",
      run: (signal) =>
        new Promise((resolve) => {
          signal.addEventListener("abort", () => resolve(undefined), { once: true });
        }),
    });

    await actTimers(5000);
    await job;

    expect(events).toContain("preload.aborted");
  });

  it("aborts capture-scoped work", async () => {
    setPreloadFeatureFlagOverrideForTest(() => true);
    const aborted = vi.fn();
    const job = schedulePreload("light:/traffic-graph", "route-enter", {
      cacheKey: "capture",
      captureKey: "capture",
      run: (signal) =>
        new Promise((resolve) => {
          signal.addEventListener(
            "abort",
            () => {
              aborted();
              resolve(undefined);
            },
            { once: true },
          );
        }),
    });

    await vi.waitFor(() => expect(aborted).not.toHaveBeenCalled());
    cancelCapturePreloads("capture");
    await job;

    expect(aborted).toHaveBeenCalledTimes(1);
  });
});

async function actTimers(ms: number) {
  vi.advanceTimersByTime(ms);
  await Promise.resolve();
}
