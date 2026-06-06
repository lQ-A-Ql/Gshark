import { describe, expect, it } from "vitest";
import { createPreloadMetricsRecorder, shouldDowngradePreload } from "./preloadMetrics";
import type { PreloadTelemetry } from "./preloadTelemetry";

const base = {
  targetId: "heavy:/c2-analysis",
  kind: "heavy-analysis",
  cost: "high",
  trigger: "hover",
} satisfies Omit<PreloadTelemetry, "event">;

describe("preload metrics", () => {
  it("summarizes hit and failure rates", () => {
    const recorder = createPreloadMetricsRecorder();
    recorder.record({ ...base, event: "preload.started" });
    recorder.record({ ...base, event: "preload.fulfilled" });
    recorder.record({ ...base, event: "preload.reused" });
    recorder.record({ ...base, event: "preload.failed" });

    expect(recorder.summary()).toMatchObject({
      started: 1,
      fulfilled: 1,
      reused: 1,
      failed: 1,
      hitRate: 0.5,
      abortFailRate: 0.3333,
    });
  });

  it("suggests downgrade when abort/fail rate is high", () => {
    expect(shouldDowngradePreload({ ...createPreloadMetricsRecorder().summary(), abortFailRate: 0.5 })).toBe("heavy-off");
  });
});
