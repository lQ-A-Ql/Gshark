import { backendClients } from "../../integrations/backendClients";
import type { RuleStatus } from "../../integrations/clients/ruleClient";
import type { PreloadJobInput } from "../../preload/preloadScheduler";

const RULE_STATUS_CACHE_KEY = "rule-status";
let ruleStatusCache: RuleStatus | undefined;
let ruleStatusInflight: Promise<RuleStatus> | undefined;

export function getRuleStatusPreloadInput(): PreloadJobInput {
  return {
    cacheKey: RULE_STATUS_CACHE_KEY,
    run: (signal) => prefetchRuleStatus(signal),
  };
}

export function readRuleStatusPreloadCache() {
  return ruleStatusCache;
}

export function resetRulePreloadForTest() {
  ruleStatusCache = undefined;
  ruleStatusInflight = undefined;
}

async function prefetchRuleStatus(signal: AbortSignal) {
  if (ruleStatusCache) return ruleStatusCache;
  if (ruleStatusInflight) return ruleStatusInflight;
  ruleStatusInflight = backendClients.rules.getRuleStatus(signal).then((status) => {
    if (!signal.aborted) {
      ruleStatusCache = status;
    }
    return status;
  });
  ruleStatusInflight.then(
    () => {
      ruleStatusInflight = undefined;
    },
    () => {
      ruleStatusInflight = undefined;
    },
  );
  return ruleStatusInflight;
}
