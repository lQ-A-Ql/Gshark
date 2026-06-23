import type { USBHIDSourceMode } from "../core/types";
import { backendClients } from "../integrations/backendClients";
import type { PreloadTrigger } from "./preloadBudget";
import { isPreloadFeatureFlagEnabled, schedulePreload } from "./preloadScheduler";
import { findPreloadTarget } from "./preloadTargets";
import { recordPreloadEvent } from "./preloadTelemetry";

type WailsDesktopWindow = Window & { go?: { main?: { DesktopApp?: unknown } } };

export type HeavyWarmupInput = {
  backendConnected: boolean;
  captureReady: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
  currentRouteIdle: boolean;
  dbcProfilePaths?: string[];
  hidSource?: USBHIDSourceMode;
  hidEventLimit?: number;
};

export async function scheduleRouteHeavyWarmup(routePath: string, trigger: PreloadTrigger, input: HeavyWarmupInput) {
  const targetId = `heavy:${routePath}`;
  if (!isDesktopRuntime()) {
    recordPreloadEvent({ event: "preload.skipped", targetId, kind: "heavy-analysis", cost: "high", trigger, reason: "not-desktop" });
    return Promise.resolve();
  }
  if (!input.backendConnected || !input.captureReady || !input.filePath || !input.currentRouteIdle) {
    recordPreloadEvent({ event: "preload.skipped", targetId, kind: "heavy-analysis", cost: "high", trigger, reason: "gate-closed" });
    return Promise.resolve();
  }
  const target = findPreloadTarget(targetId);
  if (!target) {
    recordPreloadEvent({ event: "preload.skipped", targetId, kind: "heavy-analysis", cost: "high", trigger, reason: "forbidden-target" });
    return Promise.resolve();
  }
  if (!isPreloadFeatureFlagEnabled(target.featureFlag)) {
    recordPreloadEvent({ event: "preload.skipped", targetId, kind: "heavy-analysis", cost: "high", trigger, reason: "flag-disabled" });
    return Promise.resolve();
  }
  const keyedInput = await withVehicleDBCProfilePaths(routePath, trigger, targetId, input);
  if (!keyedInput) return Promise.resolve();
  const cacheKey = buildHeavyWarmupCacheKey(routePath, keyedInput);
  if (!cacheKey) {
    recordPreloadEvent({ event: "preload.skipped", targetId, kind: "heavy-analysis", cost: "high", trigger, reason: "forbidden-target" });
    return Promise.resolve();
  }
  return schedulePreload(targetId, trigger, {
    cacheKey,
    captureKey: `${keyedInput.captureRevision}::${keyedInput.filePath}::${keyedInput.totalPackets}`,
    run: (signal) => runHeavyWarmup(routePath, keyedInput, signal),
  });
}

export function buildHeavyWarmupCacheKey(routePath: string, input: HeavyWarmupInput) {
  const base = `${input.captureRevision}::${input.filePath}::${input.totalPackets}`;
  if (routePath === "/c2-analysis") return `${base}::c2`;
  if (routePath === "/industrial-analysis") return `${base}::industrial`;
  if (routePath === "/vehicle-analysis") return `${base}::vehicle::${buildVehicleDBCProfileKey(input.dbcProfilePaths)}`;
  if (routePath === "/usb-analysis") {
    return `${base}::usb::${input.hidSource ?? "auto"}::${input.hidEventLimit ?? 20000}`;
  }
  return "";
}

async function runHeavyWarmup(routePath: string, input: HeavyWarmupInput, signal: AbortSignal) {
  if (routePath === "/c2-analysis") {
    await backendClients.analysis.getC2SampleAnalysis(signal, { source: "warmup" });
  } else if (routePath === "/industrial-analysis") {
    await backendClients.analysis.getIndustrialAnalysis(signal, { source: "warmup" });
  } else if (routePath === "/vehicle-analysis") {
    await backendClients.analysis.getVehicleAnalysis(signal, { source: "warmup" });
  } else if (routePath === "/usb-analysis") {
    await backendClients.analysis.getUSBAnalysis(signal, input.hidSource ?? "auto", input.hidEventLimit ?? 20000, { source: "warmup" });
  }
}

function isDesktopRuntime() {
  return typeof window !== "undefined" && Boolean((window as WailsDesktopWindow).go?.main?.DesktopApp);
}

async function withVehicleDBCProfilePaths(
  routePath: string,
  trigger: PreloadTrigger,
  targetId: string,
  input: HeavyWarmupInput,
): Promise<HeavyWarmupInput | undefined> {
  if (routePath !== "/vehicle-analysis" || input.dbcProfilePaths) return input;
  try {
    const profiles = await backendClients.vehicleDBC.listVehicleDBCProfiles();
    return { ...input, dbcProfilePaths: profiles.map((profile) => profile.path) };
  } catch (error) {
    recordPreloadEvent({
      event: "preload.skipped",
      targetId,
      kind: "heavy-analysis",
      cost: "high",
      trigger,
      reason: error instanceof Error ? error.message : "dbc-profile-key-failed",
    });
    return undefined;
  }
}

function buildVehicleDBCProfileKey(paths: string[] | undefined): string {
  return Array.from(new Set((paths ?? []).map((path) => path.trim()).filter(Boolean))).sort().join("|");
}
