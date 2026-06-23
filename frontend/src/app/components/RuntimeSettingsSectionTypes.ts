import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";

export type RuntimeToolAllowedDirsField = "ffmpegAllowedDirs" | "pythonAllowedDirs" | "yaraAllowedDirs";

export type RuntimeSettingsSectionProps = {
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  unknownMessage?: string;
  unknownStateText?: string;
  allowToolDir?: (field: RuntimeToolAllowedDirsField, dir: string) => Promise<void>;
  setForm: (updater: (prev: ToolRuntimeConfig) => ToolRuntimeConfig) => void;
};
