import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { toPluginItemRequest } from "./clients/pluginClient";
import { typedCall } from "./desktopTypedBridgeCore";
import { asPluginItem, asPluginItems } from "./mappers/pluginMapper";
import { asPluginSource, toPluginSourceRequest } from "./mappers/pluginSourceMapper";

export function createPluginTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async listPlugins() {
      return asPluginItems(await typedCall(() => desktopApp.ListPlugins!(), "DesktopApp.ListPlugins"));
    },
    async getPluginSource(id) {
      return asPluginSource(await typedCall(() => desktopApp.GetPluginSource!(id), "DesktopApp.GetPluginSource"), id);
    },
    async savePluginSource(source) {
      return asPluginSource(
        await typedCall(
          () => desktopApp.SavePluginSource!(toPluginSourceRequest(source)),
          "DesktopApp.SavePluginSource",
        ),
        source.id,
      );
    },
    async addPlugin(plugin) {
      return asPluginItem(
        await typedCall(() => desktopApp.AddPlugin!(toPluginItemRequest(plugin)), "DesktopApp.AddPlugin"),
      );
    },
    async deletePlugin(id) {
      await typedCall(() => desktopApp.DeletePlugin!(id), "DesktopApp.DeletePlugin");
    },
    async togglePlugin(id) {
      return asPluginItem(await typedCall(() => desktopApp.TogglePlugin!(id), "DesktopApp.TogglePlugin"));
    },
    async setPluginsEnabled(ids, enabled) {
      return asPluginItems(
        await typedCall(() => desktopApp.SetPluginsEnabled!(ids, enabled), "DesktopApp.SetPluginsEnabled"),
      );
    },
  };
}
