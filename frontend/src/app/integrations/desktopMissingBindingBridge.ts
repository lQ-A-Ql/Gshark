import type { BackendBridge } from "./bridgeTypes";
import { DesktopIpcRequestError } from "./desktopIpcControls";
import { subscribeDesktopEvents } from "./desktopEventTransport";
import { typedBindingRequirements } from "./desktopTypedBridgeRequirements";

export function createDesktopMissingBindingBridge(): BackendBridge {
  return new Proxy(
    {
      subscribeEvents: subscribeDesktopEvents,
    } as Partial<BackendBridge>,
    {
      get(target, property) {
        if (property in target) {
          return target[property as keyof BackendBridge];
        }
        if (typeof property === "symbol") {
          return undefined;
        }
        return () => {
          const endpoint = typedBindingRequirements[property] ?? property;
          return Promise.reject(
            new DesktopIpcRequestError(
              "typed_binding_required",
              `Wails desktop typed IPC binding is missing: ${endpoint}.`,
              `DesktopApp.${endpoint}`,
              0,
            ),
          );
        };
      },
    },
  ) as BackendBridge;
}
