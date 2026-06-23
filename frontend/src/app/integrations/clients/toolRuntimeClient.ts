import type {
  MCPConfig,
  MCPStatus,
  SpeechToTextStatus,
  ToolRuntimeConfig,
  ToolRuntimeSnapshot,
} from "../../core/types";
import { asToolRuntimeSnapshot } from "../mappers/runtimeMapper";
import { withToolRuntimeSnapshotMeta } from "../toolRuntimeSnapshotMeta";
import { asTSharkStatus } from "../mappers/tsharkStatusMapper";
import { asMCPStatus } from "../mappers/mcpStatusMapper";
import type {
  SpeechStatusWireDTO,
  ToolRuntimeSnapshotWireDTO,
  ToolPathStatusWireDTO,
  TSharkStatusWireDTO,
} from "../wire/runtimeWireDtos";
import type { MCPStatusWireDTO } from "../wire/mcpWireDtos";
import { asFFmpegStatus, asSpeechStatus } from "../mappers/runtimeComponentMapper";

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
  pathWarning?: string;
  extraAllowedDir?: string;
}

export interface FFmpegStatus {
  available: boolean;
  path: string;
  message: string;
  customPath?: string;
  usingCustomPath?: boolean;
  pathWarning?: string;
  extraAllowedDir?: string;
}

export type ToolRuntimeName = "tshark" | "ffmpeg" | "python" | "yara";

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
  allowTSharkDir(dir: string): Promise<TSharkStatus>;
  listTSharkAllowedDirs(): Promise<string[]>;
  removeTSharkAllowedDir(dir: string): Promise<TSharkStatus>;
  allowToolDir(tool: ToolRuntimeName, dir: string): Promise<ToolRuntimeSnapshot>;
  listToolAllowedDirs(tool: ToolRuntimeName): Promise<string[]>;
  removeToolAllowedDir(tool: ToolRuntimeName, dir: string): Promise<ToolRuntimeSnapshot>;
  getMCPStatus(signal?: AbortSignal): Promise<MCPStatus>;
  updateMCPConfig(config: MCPConfig, signal?: AbortSignal): Promise<MCPStatus>;
}

export function createToolRuntimeClient(request: JsonRequest): ToolRuntimeClient {
  return {
    async checkTShark() {
      const payload = await request<TSharkStatusWireDTO>("/api/tools/tshark");
      return asTSharkStatus(payload);
    },

    async checkFFmpeg() {
      const payload = await request<ToolPathStatusWireDTO>("/api/tools/ffmpeg");
      return asFFmpegStatus(payload);
    },

    async checkSpeechToText() {
      const payload = await request<SpeechStatusWireDTO>("/api/tools/speech-to-text");
      return asSpeechStatus(payload);
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
          tshark_allowed_dirs: config.tsharkAllowedDirs ?? [],
          ffmpeg_path: config.ffmpegPath,
          ffmpeg_allowed_dirs: config.ffmpegAllowedDirs ?? [],
          python_path: config.pythonPath,
          python_allowed_dirs: config.pythonAllowedDirs ?? [],
          vosk_model_path: config.voskModelPath,
          yara_enabled: config.yaraEnabled,
          yara_bin: config.yaraBin,
          yara_allowed_dirs: config.yaraAllowedDirs ?? [],
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

    async allowTSharkDir(dir: string) {
      const payload = await request<TSharkStatusWireDTO>("/api/tools/tshark/allow-dir", {
        method: "POST",
        body: JSON.stringify({ dir }),
      });
      return asTSharkStatus(payload);
    },

    async listTSharkAllowedDirs() {
      const payload = await request<{ dirs?: unknown }>("/api/tools/tshark/allowed-dirs");
      const list = payload.dirs;
      if (!Array.isArray(list)) return [];
      return list.map((d) => String(d ?? "")).filter((d) => d.length > 0);
    },

    async removeTSharkAllowedDir(dir: string) {
      const payload = await request<TSharkStatusWireDTO>("/api/tools/tshark/allowed-dirs/remove", {
        method: "DELETE",
        body: JSON.stringify({ dir }),
      });
      return asTSharkStatus(payload);
    },

    async allowToolDir(tool: ToolRuntimeName, dir: string) {
      const payload = await request<ToolRuntimeSnapshotWireDTO>("/api/tools/allow-dir", {
        method: "POST",
        body: JSON.stringify({ tool, dir }),
      });
      return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "http-fallback");
    },

    async listToolAllowedDirs(tool: ToolRuntimeName) {
      const payload = await request<{ dirs?: unknown }>(`/api/tools/allowed-dirs?tool=${encodeURIComponent(tool)}`);
      const list = payload.dirs;
      if (!Array.isArray(list)) return [];
      return list.map((d) => String(d ?? "")).filter((d) => d.length > 0);
    },

    async removeToolAllowedDir(tool: ToolRuntimeName, dir: string) {
      const payload = await request<ToolRuntimeSnapshotWireDTO>("/api/tools/allowed-dirs/remove", {
        method: "DELETE",
        body: JSON.stringify({ tool, dir }),
      });
      return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "http-fallback");
    },

    async getMCPStatus(signal?: AbortSignal) {
      const payload = await request<MCPStatusWireDTO>("/api/mcp/config", signal ? { signal } : undefined);
      return asMCPStatus(payload);
    },

    async updateMCPConfig(config: MCPConfig, signal?: AbortSignal) {
      const payload = await request<MCPStatusWireDTO>("/api/mcp/config", {
        method: "POST",
        signal,
        body: JSON.stringify({ enabled: config.enabled }),
      });
      return asMCPStatus(payload);
    },
  };
}

function toolRuntimeConfigPath(mode: "fast" | "full" | string): string {
  return mode === "fast" ? "/api/tools/runtime-config?probe=fast" : "/api/tools/runtime-config";
}
