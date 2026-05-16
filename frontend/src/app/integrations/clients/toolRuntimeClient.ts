import type { SpeechToTextStatus, ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import { asToolRuntimeSnapshot } from "../mappers/runtimeMapper";
import { withToolRuntimeSnapshotMeta } from "../toolRuntimeSnapshotMeta";
import { asTSharkStatus } from "../mappers/tsharkStatusMapper";
import type {
  FFmpegStatusWireDTO,
  SpeechStatusWireDTO,
  ToolRuntimeSnapshotWireDTO,
  TSharkStatusWireDTO,
} from "../wire/runtimeWireDtos";

type JsonRequest = <T>(path: string, init?: RequestInit) => Promise<T>;

export interface TSharkStatus {
  available: boolean;
  path: string;
  message: string;
  customPath: string;
  usingCustomPath: boolean;
  version?: string;
  fieldProfile?: string;
  fieldCount?: number;
  missingRequiredFields?: string[];
  missingOptionalFields?: string[];
  capabilityMessage?: string;
  capabilityCheckDegraded?: boolean;
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
  getToolRuntimeSnapshot(signal?: AbortSignal, mode?: "fast" | "full"): Promise<ToolRuntimeSnapshot>;
  updateToolRuntimeConfig(
    config: ToolRuntimeConfig,
    signal?: AbortSignal,
    mode?: "fast" | "full",
  ): Promise<ToolRuntimeSnapshot>;
  setTSharkPath(path: string): Promise<TSharkStatus>;
}

export function createToolRuntimeClient(request: JsonRequest): ToolRuntimeClient {
  return {
    async checkTShark() {
      const payload = await request<TSharkStatusWireDTO>("/api/tools/tshark");
      return asTSharkStatus(payload);
    },

    async checkFFmpeg() {
      const payload = await request<FFmpegStatusWireDTO>("/api/tools/ffmpeg");
      return {
        available: Boolean(payload.available),
        path: String(payload.path ?? ""),
        message: String(payload.message ?? ""),
      };
    },

    async checkSpeechToText() {
      const payload = await request<SpeechStatusWireDTO>("/api/tools/speech-to-text");
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

    async getToolRuntimeSnapshot(signal?: AbortSignal, mode = "full") {
      const payload = await request<ToolRuntimeSnapshotWireDTO>(
        toolRuntimeConfigPath(mode),
        signal ? { signal } : undefined,
      );
      return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "http-fallback");
    },

    async updateToolRuntimeConfig(config: ToolRuntimeConfig, signal?: AbortSignal, mode = "full") {
      const payload = await request<ToolRuntimeSnapshotWireDTO>(toolRuntimeConfigPath(mode), {
        method: "POST",
        signal,
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
      return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "http-fallback");
    },

    async setTSharkPath(path: string) {
      const payload = await request<TSharkStatusWireDTO>("/api/tools/tshark", {
        method: "POST",
        body: JSON.stringify({ path }),
      });
      return asTSharkStatus(payload);
    },
  };
}

function toolRuntimeConfigPath(mode: "fast" | "full" | string): string {
  return mode === "fast" ? "/api/tools/runtime-config?probe=fast" : "/api/tools/runtime-config";
}
