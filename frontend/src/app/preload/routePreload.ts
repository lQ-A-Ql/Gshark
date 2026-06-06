import { routeModuleLoaders, type RouteModule, type RouteModuleLoader } from "../routeModuleLoaders";
import type { PreloadTrigger } from "./preloadBudget";
import { findCodePreloadTarget } from "./preloadTargets";
import { recordPreloadEvent } from "./preloadTelemetry";

const inflightRoutePreloads = new Map<string, Promise<RouteModule>>();
let routePreloadLoaders: Record<string, RouteModuleLoader> = routeModuleLoaders;

export async function preloadRouteModule(routePath: string, trigger: PreloadTrigger = "hover"): Promise<void> {
  const target = findCodePreloadTarget(routePath);
  const telemetryBase = {
    targetId: target?.targetId ?? `code:${routePath}`,
    kind: "code" as const,
    cost: "low" as const,
    trigger,
  };
  const loader = routePreloadLoaders[routePath];
  if (!target || !loader) {
    recordPreloadEvent({ ...telemetryBase, event: "preload.skipped", reason: "unknown-route" });
    return;
  }

  const existing = inflightRoutePreloads.get(routePath);
  if (existing) {
    recordPreloadEvent({ ...telemetryBase, event: "preload.reused" });
    await existing;
    return;
  }

  const startedAt = performanceNow();
  recordPreloadEvent({ ...telemetryBase, event: "preload.started" });
  const promise = loader();
  inflightRoutePreloads.set(routePath, promise);
  try {
    await promise;
    recordPreloadEvent({
      ...telemetryBase,
      event: "preload.fulfilled",
      durationMs: Math.max(0, Math.round(performanceNow() - startedAt)),
    });
  } catch (error) {
    inflightRoutePreloads.delete(routePath);
    recordPreloadEvent({
      ...telemetryBase,
      event: "preload.failed",
      durationMs: Math.max(0, Math.round(performanceNow() - startedAt)),
      reason: error instanceof Error ? error.message : "route import failed",
    });
  }
}

export function setRoutePreloadLoadersForTest(loaders: Record<string, RouteModuleLoader>) {
  routePreloadLoaders = loaders;
  inflightRoutePreloads.clear();
}

export function resetRoutePreloadForTest() {
  routePreloadLoaders = routeModuleLoaders;
  inflightRoutePreloads.clear();
}

function performanceNow(): number {
  return typeof performance !== "undefined" && typeof performance.now === "function" ? performance.now() : Date.now();
}
