import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";

export type RuntimeSettingsSectionProps = {
  form: ToolRuntimeConfig;
  snapshot?: ToolRuntimeSnapshot | null;
  unknownMessage?: string;
  unknownStateText?: string;
  setForm: (updater: (prev: ToolRuntimeConfig) => ToolRuntimeConfig) => void;
};
export type SpeechSettingsSectionProps = RuntimeSettingsSectionProps & {
  speechIssues: string[];
  speechSummary: string;
};
