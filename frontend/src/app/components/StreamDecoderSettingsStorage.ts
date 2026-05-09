import { DEFAULT_SETTINGS, type DecoderSettings } from "./StreamDecoderTypes";

const SETTINGS_STORAGE_KEY = "gshark.stream-decoders.v1";

export function readDecoderSettings(): DecoderSettings {
  if (typeof window === "undefined") return DEFAULT_SETTINGS;
  try {
    const raw = window.localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) return DEFAULT_SETTINGS;
    const parsed = JSON.parse(raw);
    return {
      behinder: { ...DEFAULT_SETTINGS.behinder, ...(parsed.behinder ?? {}) },
      antsword: { ...DEFAULT_SETTINGS.antsword, ...(parsed.antsword ?? {}) },
      godzilla: { ...DEFAULT_SETTINGS.godzilla, ...(parsed.godzilla ?? {}) },
    };
  } catch {
    return DEFAULT_SETTINGS;
  }
}

export function persistDecoderSettings(settings: DecoderSettings) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // ignore persistence errors
  }
}
