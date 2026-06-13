import { createBridge } from "./bridgeFactory";
import { createBackendClients } from "./bridgeDomains";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

type WailsDesktopWindow = Window & { go?: { main?: { DesktopApp?: DesktopTransportBinding } } };

function getDesktopAppBinding(): DesktopTransportBinding | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }
  return (window as WailsDesktopWindow).go?.main?.DesktopApp;
}

export const bridge: BackendBridge = createBridge({
  getDesktopAppBinding,
});

export const backendClients = createBackendClients(bridge);
