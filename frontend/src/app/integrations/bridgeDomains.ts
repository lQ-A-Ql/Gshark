import type { BackendBridge, BackendClients } from "./bridgeTypes";
import { createPlaybookFromBridge } from "./playbookBridgeClient";

export function createBackendClients(bridge: BackendBridge): BackendClients {
  return {
    runtime: bridge,
    capture: bridge,
    packet: bridge,
    hunting: bridge,
    object: bridge,
    stream: bridge,
    analysis: bridge,
    evidence: bridge,
    media: bridge,
    vehicleDBC: bridge,
    securityMaterial: bridge,
    miscModule: bridge,
    playbook: createPlaybookFromBridge(bridge),
    rules: bridge,
  };
}
