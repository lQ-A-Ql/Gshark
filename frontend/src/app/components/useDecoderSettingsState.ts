import { useEffect, useState } from "react";
import {
  mergeHintIntoSettings,
  persistDecoderSettings,
  readDecoderSettings,
  type DecoderHintSource,
  type DecoderSettings,
} from "./StreamDecoderWorkbenchUtils";

export function useDecoderSettingsState(activeHintSource?: DecoderHintSource) {
  const [settings, setSettings] = useState<DecoderSettings>(() => readDecoderSettings());

  useEffect(() => {
    persistDecoderSettings(settings);
  }, [settings]);

  useEffect(() => {
    setSettings((prev) => mergeHintIntoSettings(prev, activeHintSource));
  }, [activeHintSource]);

  return { settings, setSettings };
}
