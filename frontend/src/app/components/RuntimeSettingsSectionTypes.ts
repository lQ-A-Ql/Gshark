import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";

export type RuntimeSettingsSectionProps = {
  backendConnected: boolean;
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  setForm: (updater: (prev: ToolRuntimeConfig) => ToolRuntimeConfig) => void;
};

export type SpeechSettingsSectionProps = Omit<RuntimeSettingsSectionProps, "backendConnected"> & {
  speechIssues: string[];
  speechSummary: string;
};
