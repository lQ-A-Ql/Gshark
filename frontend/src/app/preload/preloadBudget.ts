export const PRELOAD_BUDGET = {
  maxConcurrentCodePreloads: 4,
  maxConcurrentLightDataPreloads: 2,
  maxConcurrentHeavyWarmups: 1,
  hoverIntentDelayMs: 180,
  heavyHoverIntentDelayMs: 400,
  idleDelayMs: 1200,
  lightDataTimeoutMs: 5000,
  heavyWarmupTimeoutMs: 15000,
} as const;

export type PreloadKind = "code" | "light-data" | "heavy-analysis";
export type PreloadCost = "low" | "medium" | "high";
export type PreloadTrigger = "hover" | "focus" | "idle" | "capture-ready" | "manual" | "route-enter";

export function maxConcurrentPreloads(kind: PreloadKind): number {
  if (kind === "code") return PRELOAD_BUDGET.maxConcurrentCodePreloads;
  if (kind === "light-data") return PRELOAD_BUDGET.maxConcurrentLightDataPreloads;
  return PRELOAD_BUDGET.maxConcurrentHeavyWarmups;
}

export function timeoutForCost(cost: PreloadCost): number {
  if (cost === "low") return 0;
  if (cost === "medium") return PRELOAD_BUDGET.lightDataTimeoutMs;
  return PRELOAD_BUDGET.heavyWarmupTimeoutMs;
}
