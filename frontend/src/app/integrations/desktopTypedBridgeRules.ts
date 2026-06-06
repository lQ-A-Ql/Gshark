import type { RuleUpdateConfig } from "./clients/ruleClient";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedCall } from "./desktopTypedBridgeCore";

export function createRuleTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async getRuleStatus(signal) {
      return (await typedCall(() => desktopApp.GetRuleStatus!(), "DesktopApp.GetRuleStatus", signal)) as any;
    },
    async toggleRulePack(packId, enabled) {
      await typedCall(
        () => desktopApp.ToggleRulePack!(packId, enabled),
        "DesktopApp.ToggleRulePack",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
    },
    async checkRuleUpdates() {
      const payload = await typedCall(
        () => desktopApp.CheckRuleUpdates!(),
        "DesktopApp.CheckRuleUpdates",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return Array.isArray((payload as any)?.results) ? (payload as any).results : [];
    },
    async downloadRulePack(packId, url) {
      return (await typedCall(
        () => desktopApp.DownloadRulePack!(packId, url),
        "DesktopApp.DownloadRulePack",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as any;
    },
    async updateRuleConfig(config) {
      return (await typedCall(
        () => desktopApp.UpdateRuleConfig!(toRuleUpdateConfigRequest(config)),
        "DesktopApp.UpdateRuleConfig",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as any;
    },
    async listRuleConflicts() {
      const payload = await typedCall(() => desktopApp.GetRuleConflicts!(), "DesktopApp.GetRuleConflicts");
      return Array.isArray((payload as any)?.conflicts) ? (payload as any).conflicts : [];
    },
    async validateRuleContent(content) {
      return (await typedCall(
        () => desktopApp.ValidateRules!(content),
        "DesktopApp.ValidateRules",
        undefined,
        LONG_TYPED_IPC_TIMEOUT_MS,
      )) as any;
    },
  };
}

function toRuleUpdateConfigRequest(config: RuleUpdateConfig) {
  return {
    remote_url: config.remote_url,
    auto_update: config.auto_update,
    update_interval_hours: config.update_interval_hours,
    cache_dir: config.cache_dir,
  };
}
