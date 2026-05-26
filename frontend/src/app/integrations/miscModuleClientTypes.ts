import type { MiscModuleImportResult, MiscModuleManifest, MiscModuleRunResult } from "../core/types";
import type { OpenFileResult } from "./clients/captureClient";

export interface MiscModuleClient {
  listMiscModules(): Promise<MiscModuleManifest[]>;
  importMiscModulePackage(file: File): Promise<MiscModuleImportResult>;
  selectMiscModulePackage?(): Promise<OpenFileResult>;
  importMiscModulePackageFromPath?(path: string): Promise<MiscModuleImportResult>;
  deleteMiscModule(id: string): Promise<void>;
  runMiscModule(id: string, values: Record<string, string>): Promise<MiscModuleRunResult>;
}
