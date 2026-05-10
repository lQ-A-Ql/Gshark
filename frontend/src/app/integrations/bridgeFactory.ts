import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { createDesktopBridge } from "./desktopBridge";
import { createHttpBridge } from "./httpBridge";

export interface BridgeFactoryOptions {
  getDesktopAppBinding: () => DesktopTransportBinding | undefined;
}

export function createBridge(options: BridgeFactoryOptions): BackendBridge {
  const httpBridge = createHttpBridge(options);
  const desktopApp = options.getDesktopAppBinding();
  if (!desktopApp) {
    return httpBridge;
  }
  return createDesktopBridge({
    desktopApp,
    fallbackBridge: httpBridge,
  });
}
