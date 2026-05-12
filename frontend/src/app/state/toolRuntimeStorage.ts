import type { ToolRuntimeConfig } from "../core/types";

const TSHARK_PATH_STORAGE_KEY = "gshark.tshark-path.v1";
const TOOL_RUNTIME_STORAGE_KEY = "gshark.tool-runtime.v1";

export const EMPTY_TOOL_RUNTIME_CONFIG: ToolRuntimeConfig = {
  tsharkPath: "",
  ffmpegPath: "",
  pythonPath: "",
  voskModelPath: "",
  yaraEnabled: true,
  yaraBin: "",
  yaraRules: "",
  yaraTimeoutMs: 25000,
};

export function readToolRuntimeConfig(): ToolRuntimeConfig {
  if (typeof window === "undefined") return { ...EMPTY_TOOL_RUNTIME_CONFIG };
  try {
    const raw = window.localStorage.getItem(TOOL_RUNTIME_STORAGE_KEY);
    if (!raw) {
      const legacyTsharkPath = window.localStorage.getItem(TSHARK_PATH_STORAGE_KEY)?.trim() ?? "";
      return { ...EMPTY_TOOL_RUNTIME_CONFIG, tsharkPath: legacyTsharkPath };
    }
    const parsed = JSON.parse(raw);
    return {
      tsharkPath: String(parsed?.tsharkPath ?? window.localStorage.getItem(TSHARK_PATH_STORAGE_KEY) ?? "").trim(),
      ffmpegPath: String(parsed?.ffmpegPath ?? "").trim(),
      pythonPath: String(parsed?.pythonPath ?? "").trim(),
      voskModelPath: String(parsed?.voskModelPath ?? "").trim(),
      yaraEnabled: parsed?.yaraEnabled !== false,
      yaraBin: String(parsed?.yaraBin ?? "").trim(),
      yaraRules: String(parsed?.yaraRules ?? "").trim(),
      yaraTimeoutMs: Number(parsed?.yaraTimeoutMs ?? 25000) || 25000,
    };
  } catch {
    return { ...EMPTY_TOOL_RUNTIME_CONFIG };
  }
}

export function writeToolRuntimeConfig(config: ToolRuntimeConfig) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(TOOL_RUNTIME_STORAGE_KEY, JSON.stringify(config));
    if (config.tsharkPath) {
      window.localStorage.setItem(TSHARK_PATH_STORAGE_KEY, config.tsharkPath);
    }
  } catch {
    // localStorage write failed
  }
}
