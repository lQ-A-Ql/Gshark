import { PRELOAD_BUDGET, maxConcurrentPreloads, type PreloadTrigger } from "./preloadBudget";
import { isCodeOnlyRollbackEnabled, isTargetDisabledByRuntimeFlag } from "./preloadFlags";
import { findPreloadTarget } from "./preloadTargets";
import { recordPreloadEvent } from "./preloadTelemetry";

type DataPreloadKind = "light-data" | "heavy-analysis";

export type PreloadJobInput = {
  cacheKey?: string;
  captureKey?: string;
  run: (signal: AbortSignal) => Promise<unknown>;
};

type QueueItem = {
  key: string;
  targetId: string;
  trigger: PreloadTrigger;
  input: PreloadJobInput;
  controller: AbortController;
  resolve: () => void;
};

const queues = {
  "light-data": [] as QueueItem[],
  "heavy-analysis": [] as QueueItem[],
};

const activeCounts = {
  "light-data": 0,
  "heavy-analysis": 0,
};

const inflight = new Map<string, Promise<void>>();
const controllersByCaptureKey = new Map<string, Set<AbortController>>();
let featureFlagOverrideForTest: ((featureFlag: string) => boolean | undefined) | undefined;

export function schedulePreload(targetId: string, trigger: PreloadTrigger, input: PreloadJobInput): Promise<void> {
  const target = findPreloadTarget(targetId);
  if (!target || target.kind === "code") {
    recordPreloadEvent({
      event: "preload.skipped",
      targetId,
      kind: target?.kind ?? "light-data",
      cost: target?.cost ?? "medium",
      trigger,
      reason: target ? "code-target" : "unknown-target",
    });
    return Promise.resolve();
  }
  if (isCodeOnlyRollbackEnabled() || isTargetDisabledByRuntimeFlag(targetId)) {
    recordPreloadEvent({ event: "preload.skipped", targetId, kind: target.kind, cost: target.cost, trigger, reason: "target-disabled" });
    return Promise.resolve();
  }
  const kind = target.kind as DataPreloadKind;
  if (!target.enabledByDefault && !isPreloadFeatureFlagEnabled(target.featureFlag)) {
    recordPreloadEvent({ event: "preload.skipped", targetId, kind: target.kind, cost: target.cost, trigger, reason: "flag-disabled" });
    return Promise.resolve();
  }

  const key = `${targetId}::${input.cacheKey ?? ""}`;
  const existing = inflight.get(key);
  if (existing) {
    recordPreloadEvent({ event: "preload.reused", targetId, kind: target.kind, cost: target.cost, trigger });
    return existing;
  }

  const controller = new AbortController();
  if (input.captureKey) {
    let set = controllersByCaptureKey.get(input.captureKey);
    if (!set) {
      set = new Set();
      controllersByCaptureKey.set(input.captureKey, set);
    }
    set.add(controller);
  }

  const promise = new Promise<void>((resolve) => {
    queues[kind].push({ key, targetId, trigger, input, controller, resolve });
    drainQueue(kind);
  });
  inflight.set(key, promise);
  promise.finally(() => inflight.delete(key));
  return promise;
}

export function cancelCapturePreloads(captureKey: string): void {
  const controllers = controllersByCaptureKey.get(captureKey);
  if (!controllers) return;
  for (const controller of controllers) controller.abort();
  controllersByCaptureKey.delete(captureKey);
}

export function resetPreloadSchedulerForTest() {
  queues["light-data"].splice(0);
  queues["heavy-analysis"].splice(0);
  activeCounts["light-data"] = 0;
  activeCounts["heavy-analysis"] = 0;
  inflight.clear();
  controllersByCaptureKey.clear();
  featureFlagOverrideForTest = undefined;
}

export function setPreloadFeatureFlagOverrideForTest(override: ((featureFlag: string) => boolean | undefined) | undefined) {
  featureFlagOverrideForTest = override;
}

function drainQueue(kind: DataPreloadKind) {
  const maxConcurrent = maxConcurrentPreloads(kind);
  while (activeCounts[kind] < maxConcurrent && queues[kind].length > 0) {
    const item = queues[kind].shift()!;
    void runQueueItem(kind, item);
  }
}

async function runQueueItem(kind: DataPreloadKind, item: QueueItem) {
  const target = findPreloadTarget(item.targetId);
  if (!target) {
    item.resolve();
    return;
  }
  if (item.controller.signal.aborted) {
    recordPreloadEvent({ event: "preload.aborted", targetId: item.targetId, kind: target.kind, cost: target.cost, trigger: item.trigger });
    item.resolve();
    drainQueue(kind);
    return;
  }
  activeCounts[kind] += 1;
  const startedAt = performanceNow();
  recordPreloadEvent({ event: "preload.started", targetId: item.targetId, kind: target.kind, cost: target.cost, trigger: item.trigger });
  const timeoutMs = target.timeoutMs || (target.cost === "high" ? PRELOAD_BUDGET.heavyWarmupTimeoutMs : PRELOAD_BUDGET.lightDataTimeoutMs);
  const timeout = setTimeout(() => item.controller.abort(), timeoutMs);
  try {
    await item.input.run(item.controller.signal);
    if (item.controller.signal.aborted) {
      recordPreloadEvent({ event: "preload.aborted", targetId: item.targetId, kind: target.kind, cost: target.cost, trigger: item.trigger });
    } else {
      recordPreloadEvent({
        event: "preload.fulfilled",
        targetId: item.targetId,
        kind: target.kind,
        cost: target.cost,
        trigger: item.trigger,
        durationMs: Math.max(0, Math.round(performanceNow() - startedAt)),
      });
    }
  } catch (error) {
    recordPreloadEvent({
      event: item.controller.signal.aborted ? "preload.aborted" : "preload.failed",
      targetId: item.targetId,
      kind: target.kind,
      cost: target.cost,
      trigger: item.trigger,
      reason: error instanceof Error ? error.message : "preload failed",
    });
  } finally {
    clearTimeout(timeout);
    if (item.input.captureKey) controllersByCaptureKey.get(item.input.captureKey)?.delete(item.controller);
    activeCounts[kind] -= 1;
    item.resolve();
    drainQueue(kind);
  }
}

export function isPreloadFeatureFlagEnabled(featureFlag: string | undefined): boolean {
  if (!featureFlag) return true;
  const override = featureFlagOverrideForTest?.(featureFlag);
  if (override !== undefined) return override;
  return String((import.meta.env as Record<string, unknown>)[featureFlag] ?? "").trim() === "1";
}

function performanceNow(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now() : Date.now();
}
