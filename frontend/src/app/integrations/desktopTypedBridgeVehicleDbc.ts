import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { typedCall } from "./desktopTypedBridgeCore";
import { asDBCProfiles } from "./mappers/pluginMapper";

export function createVehicleDbcTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async listVehicleDBCProfiles() {
      return asDBCProfiles(
        await typedCall(() => desktopApp.ListVehicleDBCProfiles!(), "DesktopApp.ListVehicleDBCProfiles"),
      );
    },
    async addVehicleDBC(path: string) {
      return asDBCProfiles(await typedCall(() => desktopApp.AddVehicleDBC!(path), "DesktopApp.AddVehicleDBC"));
    },
    async removeVehicleDBC(path: string) {
      return asDBCProfiles(await typedCall(() => desktopApp.RemoveVehicleDBC!(path), "DesktopApp.RemoveVehicleDBC"));
    },
  };
}
