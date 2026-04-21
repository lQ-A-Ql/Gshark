import type { ComponentType } from "react";
import type { MiscModuleRendererProps } from "./types";
import { GenericMiscModule } from "./modules/GenericMiscModule";
import { SMB3SessionKeyModule } from "./modules/SMB3SessionKeyModule";
import { WinRMDecryptModule } from "./modules/WinRMDecryptModule";

const moduleRenderers: Record<string, ComponentType<MiscModuleRendererProps>> = {
  "winrm-decrypt": WinRMDecryptModule,
  "smb3-session-key": SMB3SessionKeyModule,
};

export function resolveMiscModuleRenderer(moduleID: string): ComponentType<MiscModuleRendererProps> {
  return moduleRenderers[moduleID] ?? GenericMiscModule;
}
