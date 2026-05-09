import type { Dispatch, SetStateAction } from "react";

import {
  AntSwordSettingsSection,
  BehinderSettingsSection,
  GodzillaSettingsSection,
} from "./StreamDecoderSettingsSections";
import type { DecoderSettings } from "./StreamDecoderWorkbenchUtils";

export type DecoderSettingsKind = "behinder" | "antsword" | "godzilla";

type StreamDecoderSettingsPanelProps = {
  activeSettings: DecoderSettingsKind;
  settings: DecoderSettings;
  setSettings: Dispatch<SetStateAction<DecoderSettings>>;
  onClose: () => void;
};

export function StreamDecoderSettingsPanel({
  activeSettings,
  settings,
  setSettings,
  onClose,
}: StreamDecoderSettingsPanelProps) {
  return (
    <div className="mt-4 rounded-lg border border-border bg-background/80 p-4">
      {activeSettings === "behinder" && (
        <BehinderSettingsSection settings={settings} setSettings={setSettings} onClose={onClose} />
      )}
      {activeSettings === "antsword" && (
        <AntSwordSettingsSection settings={settings} setSettings={setSettings} onClose={onClose} />
      )}
      {activeSettings === "godzilla" && (
        <GodzillaSettingsSection settings={settings} setSettings={setSettings} onClose={onClose} />
      )}
    </div>
  );
}
