import type { ToolRuntimeConfig, ToolRuntimeSnapshot } from "../core/types";

export function buildOfflineToolRuntimeSnapshot(config: ToolRuntimeConfig): ToolRuntimeSnapshot {
  return {
    config,
    tshark: {
      available: false,
      path: "",
      message: "后端未连接",
      customPath: config.tsharkPath || undefined,
      usingCustomPath: Boolean(config.tsharkPath),
    },
    ffmpeg: {
      available: false,
      path: "",
      message: "后端未连接",
      customPath: config.ffmpegPath || undefined,
      usingCustomPath: Boolean(config.ffmpegPath),
    },
    speech: {
      available: false,
      engine: "vosk",
      language: "zh-CN",
      pythonAvailable: false,
      ffmpegAvailable: false,
      voskAvailable: false,
      modelAvailable: false,
      modelPath: config.voskModelPath || undefined,
      message: "后端未连接",
    },
    yara: {
      available: false,
      enabled: config.yaraEnabled,
      message: "后端未连接",
      customBin: config.yaraBin || undefined,
      customRules: config.yaraRules || undefined,
      usingCustomBin: Boolean(config.yaraBin),
      usingCustomRules: Boolean(config.yaraRules),
      timeoutMs: config.yaraTimeoutMs,
    },
  };
}
