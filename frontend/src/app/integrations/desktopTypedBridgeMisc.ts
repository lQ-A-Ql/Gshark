import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { typedCall } from "./desktopTypedBridgeCore";
import { asMiscModuleImportResult, asMiscModuleManifests, asMiscModuleRunResult } from "./mappers/toolMapper";

export function createMiscTypedOverrides(desktopApp: DesktopTransportBinding): Partial<BackendBridge> {
  return {
    async listMiscModules() {
      return asMiscModuleManifests(await typedCall(() => desktopApp.ListMiscModules!(), "DesktopApp.ListMiscModules"));
    },
    async selectMiscModulePackage() {
      const result = await typedCall(
        () => desktopApp.SelectMiscModulePackage!(),
        "DesktopApp.SelectMiscModulePackage",
      );
      if (!result?.filePath) {
        throw new Error("未选择模块 ZIP");
      }
      return {
        filePath: String(result.filePath),
        fileSize: Number(result.fileSize ?? 0),
        fileName: String(result.fileName ?? String(result.filePath).split(/[\\/]/).pop() ?? "module.zip"),
      };
    },
    async importMiscModulePackageFromPath(path: string) {
      return asMiscModuleImportResult(
        await typedCall(
          () => desktopApp.ImportMiscModulePackageFromPath!(path),
          "DesktopApp.ImportMiscModulePackageFromPath",
        ),
      );
    },
    async deleteMiscModule(id: string) {
      await typedCall(() => desktopApp.DeleteMiscModulePackage!(id), "DesktopApp.DeleteMiscModulePackage");
    },
    async runMiscModule(id: string, values: Record<string, string>) {
      return asMiscModuleRunResult(
        await typedCall(() => desktopApp.RunMiscModulePackage!(id, values), "DesktopApp.RunMiscModulePackage"),
      );
    },
  };
}
