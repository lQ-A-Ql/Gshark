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

export type ToolRuntimeProbeMode = "fast" | "full";
export type ToolRuntimeProbeState =
  | "fast_ready"
  | "full_ready"
  | "partial"
  | "timeout"
  | "failed"
  | "background_probing";

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
    version?: string;
    fieldProfile?: string;
    fieldCount?: number;
    missingRequiredFields?: string[];
    missingOptionalFields?: string[];
    capabilityMessage?: string;
    capabilityCheckDegraded?: boolean;
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
  probeMode?: ToolRuntimeProbeMode | string;
  probeState?: ToolRuntimeProbeState | string;
  probeTimings?: Record<string, number>;
  probeErrors?: Record<string, string>;
  cached?: boolean;
  updatedAt?: string;
  transport?: "desktop-ipc" | "http-fallback" | "unknown";
  transportError?: string;
}
