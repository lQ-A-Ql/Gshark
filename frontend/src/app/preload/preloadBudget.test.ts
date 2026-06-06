import { describe, expect, it } from "vitest";
import { PRELOAD_BUDGET, maxConcurrentPreloads, timeoutForCost } from "./preloadBudget";

describe("preload budget", () => {
  it("maps kind to concurrency budget", () => {
    expect(maxConcurrentPreloads("code")).toBe(PRELOAD_BUDGET.maxConcurrentCodePreloads);
    expect(maxConcurrentPreloads("light-data")).toBe(PRELOAD_BUDGET.maxConcurrentLightDataPreloads);
    expect(maxConcurrentPreloads("heavy-analysis")).toBe(PRELOAD_BUDGET.maxConcurrentHeavyWarmups);
  });

  it("maps cost to timeout budget", () => {
    expect(timeoutForCost("low")).toBe(0);
    expect(timeoutForCost("medium")).toBe(PRELOAD_BUDGET.lightDataTimeoutMs);
    expect(timeoutForCost("high")).toBe(PRELOAD_BUDGET.heavyWarmupTimeoutMs);
  });
});
