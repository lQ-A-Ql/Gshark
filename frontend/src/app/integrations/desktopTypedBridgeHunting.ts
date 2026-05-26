import type { HuntingRuntimeConfig } from "./clients/huntingClient";
import { asHuntingRuntimeConfig } from "./clients/huntingClient";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { LONG_TYPED_IPC_TIMEOUT_MS, typedCall } from "./desktopTypedBridgeCore";
import { asThreatHit } from "./mappers/packetStreamMapper";

export function createHuntingTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async listThreatHits(prefixes = ["flag{", "ctf{"], signal) {
      const rows = await typedCall(
        () => desktopApp.ListThreatHits!(prefixes),
        "DesktopApp.ListThreatHits",
        signal,
        LONG_TYPED_IPC_TIMEOUT_MS,
      );
      return Array.isArray(rows) ? rows.map(asThreatHit) : [];
    },
    async getHuntingRuntimeConfig() {
      return asHuntingRuntimeConfig(
        await typedCall(() => desktopApp.GetHuntingRuntimeConfig!(), "DesktopApp.GetHuntingRuntimeConfig"),
      );
    },
    async updateHuntingRuntimeConfig(config) {
      return asHuntingRuntimeConfig(
        await typedCall(
          () => desktopApp.UpdateHuntingRuntimeConfig!(toHuntingRuntimeConfigRequest(config)),
          "DesktopApp.UpdateHuntingRuntimeConfig",
          undefined,
          LONG_TYPED_IPC_TIMEOUT_MS,
        ),
      );
    },
  };
}

function toHuntingRuntimeConfigRequest(config: HuntingRuntimeConfig) {
  return {
    prefixes: config.prefixes,
    yara_enabled: config.yaraEnabled,
    yara_bin: config.yaraBin,
    yara_rules: config.yaraRules,
    yara_timeout_ms: config.yaraTimeoutMs,
  };
}
