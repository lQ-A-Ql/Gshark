import { evidencePreloadContract } from "../features/evidence/useEvidence";
import { getHuntingRuntimeConfigPreloadInput } from "../features/hunting/huntingPreload";
import { getRuleStatusPreloadInput } from "../features/rules/rulePreload";
import { trafficStatsPreloadContract } from "../features/traffic/useTrafficGraph";
import type { PreloadTrigger } from "./preloadBudget";
import { schedulePreload } from "./preloadScheduler";

export type CapturePreloadInput = {
  backendConnected: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
};

export function scheduleRouteLightDataPreload(routePath: string, trigger: PreloadTrigger, input: CapturePreloadInput) {
  if (routePath === "/traffic-graph") {
    const cacheKey = trafficStatsPreloadContract.getCacheKey(input);
    return schedulePreload("light:/traffic-graph", trigger, {
      cacheKey,
      captureKey: cacheKey,
      run: (signal) => trafficStatsPreloadContract.prefetch(input, signal),
    });
  }
  if (routePath === "/evidence") {
    const evidenceInput = { ...input, modules: ["hunting"] };
    const cacheKey = evidencePreloadContract.getCacheKey(evidenceInput);
    return schedulePreload("light:/evidence", trigger, {
      cacheKey,
      captureKey: cacheKey,
      run: (signal) => evidencePreloadContract.prefetch(evidenceInput, signal),
    });
  }
  if (routePath === "/hunting") {
    return schedulePreload("light:/hunting", trigger, getHuntingRuntimeConfigPreloadInput());
  }
  if (routePath === "/rules") {
    return schedulePreload("light:/rules", trigger, getRuleStatusPreloadInput());
  }
  return Promise.resolve();
}
