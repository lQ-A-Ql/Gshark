import type { SpeechToTextStatus, ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import { asToolRuntimeSnapshot } from "../mappers/runtimeMapper";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface TSharkStatus {
  available: boolean;
  path: string;
  message: string;
  customPath: string;
  usingCustomPath: boolean;
}

export interface FFmpegStatus {
  available: boolean;
  path: string;
  message: string;
}

export interface ToolRuntimeClient {
  checkTShark(): Promise<TSharkStatus>;
  checkFFmpeg(): Promise<FFmpegStatus>;
  checkSpeechToText(): Promise<SpeechToTextStatus>;
  getToolRuntimeSnapshot(): Promise<ToolRuntimeSnapshot>;
  updateToolRuntimeConfig(config: ToolRuntimeConfig): Promise<ToolRuntimeSnapshot>;
  setTSharkPath(path: string): Promise<TSharkStatus>;
}

export function createToolRuntimeClient(request: JsonRequest): ToolRuntimeClient {
  return {
    async checkTShark() {
      const payload = await request<any>("/api/tools/tshark");
      return {
        available: Boolean(payload.available),
        path: String(payload.path ?? ""),
        message: String(payload.message ?? ""),
        customPath: String(payload.custom_path ?? ""),
        usingCustomPath: Boolean(payload.using_custom_path),
      };
    },

    async checkFFmpeg() {
      const payload = await request<any>("/api/tools/ffmpeg");
      return {
        available: Boolean(payload.available),
        path: String(payload.path ?? ""),
        message: String(payload.message ?? ""),
      };
    },

    async checkSpeechToText() {
      const payload = await request<any>("/api/tools/speech-to-text");
      return {
        available: Boolean(payload.available),
        engine: String(payload.engine ?? ""),
        language: String(payload.language ?? ""),
        pythonAvailable: Boolean(payload.python_available),
        pythonCommand: String(payload.python_command ?? "") || undefined,
        ffmpegAvailable: Boolean(payload.ffmpeg_available),
        voskAvailable: Boolean(payload.vosk_available),
        modelAvailable: Boolean(payload.model_available),
        modelPath: String(payload.model_path ?? "") || undefined,
        message: String(payload.message ?? ""),
      };
    },

    async getToolRuntimeSnapshot() {
      const payload = await request<any>("/api/tools/runtime-config");
      return asToolRuntimeSnapshot(payload);
    },

    async updateToolRuntimeConfig(config: ToolRuntimeConfig) {
      const payload = await request<any>("/api/tools/runtime-config", {
        method: "POST",
        body: JSON.stringify({
          tshark_path: config.tsharkPath,
          ffmpeg_path: config.ffmpegPath,
          python_path: config.pythonPath,
          vosk_model_path: config.voskModelPath,
          yara_enabled: config.yaraEnabled,
          yara_bin: config.yaraBin,
          yara_rules: config.yaraRules,
          yara_timeout_ms: config.yaraTimeoutMs,
        }),
      });
      return asToolRuntimeSnapshot(payload);
    },

    async setTSharkPath(path: string) {
      const payload = await request<any>("/api/tools/tshark", {
        method: "POST",
        body: JSON.stringify({ path }),
      });
      return {
        available: Boolean(payload.available),
        path: String(payload.path ?? ""),
        message: String(payload.message ?? ""),
        customPath: String(payload.custom_path ?? ""),
        usingCustomPath: Boolean(payload.using_custom_path),
      };
    },
  };
}
