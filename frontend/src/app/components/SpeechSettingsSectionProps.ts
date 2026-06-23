import type { RuntimeSettingsSectionProps } from "./RuntimeSettingsSectionTypes";

export type SpeechSettingsSectionProps = RuntimeSettingsSectionProps & {
  speechIssues: string[];
  speechSummary: string;
};
