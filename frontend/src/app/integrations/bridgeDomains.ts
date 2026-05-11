import type { BackendBridge, BackendClients } from "./bridgeTypes";

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
    plugin: bridge,
    securityMaterial: bridge,
    miscModule: bridge,
  };
}
