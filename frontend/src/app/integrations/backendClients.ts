import { createBridge } from "./bridgeFactory";
import { createBackendClients } from "./bridgeDomains";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

function getDesktopAppBinding(): DesktopTransportBinding | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }
  return (window as any)?.go?.main?.DesktopApp as DesktopTransportBinding | undefined;
}

export const bridge: BackendBridge = createBridge({
  getDesktopAppBinding,
});

export const backendClients = createBackendClients(bridge);
