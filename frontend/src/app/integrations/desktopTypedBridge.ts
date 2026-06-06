import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { typedBindingRequirements } from "./desktopTypedBridgeRequirements";
import { createAnalysisEvidenceTypedOverrides } from "./desktopTypedBridgeAnalysis";
import { createHuntingTypedOverrides } from "./desktopTypedBridgeHunting";
import { createMediaTypedOverrides } from "./desktopTypedBridgeMedia";
import { createMiscTypedOverrides } from "./desktopTypedBridgeMisc";
import { createObjectToolingTypedOverrides } from "./desktopTypedBridgeTooling";
import { createPacketTypedOverrides } from "./desktopTypedBridgePacket";
import { createRuleTypedOverrides } from "./desktopTypedBridgeRules";
import { createStreamTypedOverrides } from "./desktopTypedBridgeStream";
import { createVehicleDbcTypedOverrides } from "./desktopTypedBridgeVehicleDbc";

export function createTypedDesktopOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  const overrides: Partial<BackendBridge> = {
    ...createStreamTypedOverrides(desktopApp),
    ...createObjectToolingTypedOverrides(desktopApp),
    ...createAnalysisEvidenceTypedOverrides(desktopApp),
    ...createMediaTypedOverrides(desktopApp),
    ...createPacketTypedOverrides(desktopApp),
    ...createHuntingTypedOverrides(desktopApp),
    ...createVehicleDbcTypedOverrides(desktopApp),
    ...createMiscTypedOverrides(desktopApp),
    ...createRuleTypedOverrides(desktopApp),
  };
  for (const [bridgeMethod, bindingMethod] of Object.entries(typedBindingRequirements)) {
    if (!desktopApp[bindingMethod]) {
      delete (overrides as Record<string, unknown>)[bridgeMethod];
    }
  }
  return overrides;
}
