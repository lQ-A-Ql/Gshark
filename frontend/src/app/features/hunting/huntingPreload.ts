import type { HuntingRuntimeConfig } from "../../integrations/clients/huntingClient";
import { backendClients } from "../../integrations/backendClients";
import type { PreloadJobInput } from "../../preload/preloadScheduler";

const HUNTING_RUNTIME_CONFIG_CACHE_KEY = "hunting-runtime-config";
let huntingRuntimeConfigCache: HuntingRuntimeConfig | undefined;
let huntingRuntimeConfigInflight: Promise<HuntingRuntimeConfig> | undefined;

export function getHuntingRuntimeConfigPreloadInput(): PreloadJobInput {
  return {
    cacheKey: HUNTING_RUNTIME_CONFIG_CACHE_KEY,
    run: (signal) => prefetchHuntingRuntimeConfig(signal),
  };
}

export function readHuntingRuntimeConfigPreloadCache() {
  return huntingRuntimeConfigCache;
}

export function resetHuntingPreloadForTest() {
  huntingRuntimeConfigCache = undefined;
  huntingRuntimeConfigInflight = undefined;
}

async function prefetchHuntingRuntimeConfig(signal: AbortSignal) {
  if (huntingRuntimeConfigCache) return huntingRuntimeConfigCache;
  if (huntingRuntimeConfigInflight) return huntingRuntimeConfigInflight;
  huntingRuntimeConfigInflight = backendClients.hunting.getHuntingRuntimeConfig(signal).then((config) => {
    if (!signal.aborted) {
      huntingRuntimeConfigCache = config;
    }
    return config;
  });
  huntingRuntimeConfigInflight.then(
    () => {
      huntingRuntimeConfigInflight = undefined;
    },
    () => {
      huntingRuntimeConfigInflight = undefined;
    },
  );
  return huntingRuntimeConfigInflight;
}
