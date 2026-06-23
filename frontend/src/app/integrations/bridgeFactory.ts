import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { createDesktopBridge } from "./desktopBridge";
import { createHttpBridge } from "./httpBridge";

export interface BridgeFactoryOptions {
  getDesktopAppBinding: () => DesktopTransportBinding | undefined;
}

export function createBridge(options: BridgeFactoryOptions): BackendBridge {
  let desktopApp: DesktopTransportBinding | undefined;
  let desktopBridge: BackendBridge | undefined;
  let browserHttpBridge: BackendBridge | undefined;

  const resolveBridge = () => {
    const currentDesktopApp = options.getDesktopAppBinding();
    if (!currentDesktopApp) {
      desktopApp = undefined;
      desktopBridge = undefined;
      browserHttpBridge ??= createHttpBridge(options);
      return browserHttpBridge;
    }
    if (currentDesktopApp !== desktopApp || !desktopBridge) {
      desktopApp = currentDesktopApp;
      desktopBridge = createDesktopBridge({
        desktopApp: currentDesktopApp,
      });
    }
    return desktopBridge;
  };

  return new Proxy({} as BackendBridge, {
    get(_target, property) {
      const bridge = resolveBridge();
      const value = (bridge as unknown as Record<PropertyKey, unknown>)[property];
      return typeof value === "function" ? value.bind(bridge) : value;
    },
  });
}
