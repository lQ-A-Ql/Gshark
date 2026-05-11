import type { Dispatch, SetStateAction } from "react";

import type { DecoderSettings } from "./StreamDecoderWorkbenchUtils";

export type DecoderSettingsSectionProps = {
  settings: DecoderSettings;
  setSettings: Dispatch<SetStateAction<DecoderSettings>>;
  onClose: () => void;
};

export function clampNumericText(value: string) {
  return Math.max(0, Number(value.replace(/[^0-9]/g, "")) || 0);
}
