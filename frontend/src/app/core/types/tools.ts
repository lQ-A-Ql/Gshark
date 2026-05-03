import type { SpeechToTextStatus } from "./media";

export interface ToolRuntimeConfig {
  tsharkPath: string;
  ffmpegPath: string;
  pythonPath: string;
  voskModelPath: string;
  yaraEnabled: boolean;
  yaraBin: string;
  yaraRules: string;
  yaraTimeoutMs: number;
}

export interface YaraToolStatus {
  available: boolean;
  enabled: boolean;
  path?: string;
  rulePath?: string;
  message: string;
  lastScanMessage?: string;
  customBin?: string;
  customRules?: string;
  usingCustomBin: boolean;
  usingCustomRules: boolean;
  timeoutMs: number;
}

export interface ToolRuntimeSnapshot {
  config: ToolRuntimeConfig;
  tshark: {
    available: boolean;
    path: string;
    message: string;
    customPath?: string;
    usingCustomPath: boolean;
  };
  ffmpeg: {
    available: boolean;
    path: string;
    message: string;
    customPath?: string;
    usingCustomPath: boolean;
  };
  speech: SpeechToTextStatus;
  yara: YaraToolStatus;
}
