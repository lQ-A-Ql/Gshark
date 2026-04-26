import type { MiscModuleManifest } from "../core/types";

export interface MiscModuleRendererProps {
  module: MiscModuleManifest;
  onModuleDeleted?: (moduleId: string) => Promise<void> | void;
  surfaceVariant?: "card" | "embedded";
}
