import type { DecryptionConfig, MCPConfig, MCPStatus, SpeechToTextStatus, ToolRuntimeConfig } from "../core/types";
import {
  asCaptureStatus,
  asPacketsPageResult,
  withCaptureStatusMeta,
  withPacketsPageMeta,
} from "./clients/captureClient";
import type { FFmpegStatus, TSharkStatus } from "./clients/toolRuntimeClient";
import { asToolRuntimeSnapshot } from "./mappers/runtimeMapper";
import { asTSharkStatus } from "./mappers/tsharkStatusMapper";
import { asMCPStatus } from "./mappers/mcpStatusMapper";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./mappers/tlsMapper";
import { withToolRuntimeSnapshotMeta } from "./toolRuntimeSnapshotMeta";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { createTypedDesktopOverrides } from "./desktopTypedBridge";
import { createDesktopMissingBindingBridge } from "./desktopMissingBindingBridge";
import { DesktopIpcRequestError, withDesktopIpcControls } from "./desktopIpcControls";
import { asPlainObject } from "./mappers/mapperPrimitives";
import type { MCPStatusWireDTO } from "./wire/mcpWireDtos";

interface DesktopBridgeContext {
  desktopApp: DesktopTransportBinding;
}

const FAST_RUNTIME_IPC_TIMEOUT_MS = 2000;
const DEFAULT_TYPED_IPC_TIMEOUT_MS = 10000;
const START_CAPTURE_IPC_TIMEOUT_MS = 15000;

export function createDesktopBridge({ desktopApp }: DesktopBridgeContext): BackendBridge {
  const missingBindingBridge = createDesktopMissingBindingBridge();
  const getToolRuntimeSnapshot: BackendBridge["getToolRuntimeSnapshot"] = async (signal, mode = "full") => {
    const ipcSnapshot = runtimeSnapshotMethod(desktopApp, mode);
    if (!ipcSnapshot) {
      throw missingTypedBindingError(`DesktopApp.GetToolRuntimeSnapshot(${mode})`);
    }
    const payload = await withDesktopIpcControls(ipcSnapshot, {
      endpoint: `DesktopApp.GetToolRuntimeSnapshot(${mode})`,
      responseKind: "typed-ipc",
      signal,
      timeoutMs: mode === "fast" ? FAST_RUNTIME_IPC_TIMEOUT_MS : DEFAULT_TYPED_IPC_TIMEOUT_MS,
    });
    return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "desktop-ipc");
  };

  const bridge: Partial<BackendBridge> = {
    ...createTypedDesktopOverrides(desktopApp),
    async isAvailable() {
      try {
        if (desktopApp.IsBackendReady) {
          const backendReady = await desktopApp.IsBackendReady();
          if (!backendReady) {
            return false;
          }
        }
        if (!desktopApp.PingBackendDataPlane) {
          return false;
        }
        const probe = await desktopApp.PingBackendDataPlane();
        return Boolean((probe as { ready?: unknown })?.ready);
      } catch {
        return false;
      }
    },
    async getDesktopBackendStatus() {
      if (!desktopApp.BackendStatus) {
        return "";
      }
      return String(await desktopApp.BackendStatus()).trim();
    },
    getToolRuntimeSnapshot,

    async checkTShark(): Promise<TSharkStatus> {
      try {
        const snapshot = await getToolRuntimeSnapshot();
        return { ...snapshot.tshark, customPath: snapshot.tshark.customPath ?? "" };
      } catch {
        return { available: false, path: "", message: "tshark status probe failed", customPath: "", usingCustomPath: false };
      }
    },
    async checkFFmpeg(): Promise<FFmpegStatus> {
      try {
        const snapshot = await getToolRuntimeSnapshot();
        return snapshot.ffmpeg;
      } catch {
        return { available: false, path: "", message: "ffmpeg status probe failed" };
      }
    },
    async checkSpeechToText(): Promise<SpeechToTextStatus> {
      try {
        const snapshot = await getToolRuntimeSnapshot();
        return snapshot.speech;
      } catch {
        return {
          available: false,
          engine: "",
          language: "",
          pythonAvailable: false,
          ffmpegAvailable: false,
          voskAvailable: false,
          modelAvailable: false,
          message: "speech status probe failed",
        };
      }
    },
    async updateToolRuntimeConfig(config: ToolRuntimeConfig, signal?: AbortSignal, mode = "full") {
      const ipcUpdate = runtimeConfigUpdateMethod(desktopApp, mode);
      if (!ipcUpdate) {
        throw missingTypedBindingError(`DesktopApp.UpdateToolRuntimeConfig(${mode})`);
      }
      const payload = await withDesktopIpcControls(() => ipcUpdate(toToolRuntimeRequest(config)), {
        endpoint: `DesktopApp.UpdateToolRuntimeConfig(${mode})`,
        responseKind: "typed-ipc",
        signal,
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "desktop-ipc");
    },
    async setTSharkPath(path: string): Promise<TSharkStatus> {
      if (!desktopApp.SetTSharkPath) {
        throw missingTypedBindingError("DesktopApp.SetTSharkPath");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.SetTSharkPath!(path), {
        endpoint: "DesktopApp.SetTSharkPath",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      const status = asPlainObject(payload) ?? {};
      return {
        available: Boolean(status.available),
        path: String(status.path ?? ""),
        message: String(status.message ?? ""),
        customPath: String(status.custom_path ?? ""),
        usingCustomPath: Boolean(status.using_custom_path),
        pathWarning: String(status.path_warning ?? "") || undefined,
        extraAllowedDir: String(status.extra_allowed_dir ?? "") || undefined,
      };
    },
    async allowTSharkDir(dir: string): Promise<TSharkStatus> {
      if (!desktopApp.AllowTSharkDir) {
        throw missingTypedBindingError("DesktopApp.AllowTSharkDir");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.AllowTSharkDir!(dir), {
        endpoint: "DesktopApp.AllowTSharkDir",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return asTSharkStatusFromPayload(payload);
    },
    async listTSharkAllowedDirs(): Promise<string[]> {
      if (!desktopApp.ListTSharkAllowedDirs) {
        throw missingTypedBindingError("DesktopApp.ListTSharkAllowedDirs");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.ListTSharkAllowedDirs!(), {
        endpoint: "DesktopApp.ListTSharkAllowedDirs",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return dirsFromPayload(payload);
    },
    async removeTSharkAllowedDir(dir: string): Promise<TSharkStatus> {
      if (!desktopApp.RemoveTSharkAllowedDir) {
        throw missingTypedBindingError("DesktopApp.RemoveTSharkAllowedDir");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.RemoveTSharkAllowedDir!(dir), {
        endpoint: "DesktopApp.RemoveTSharkAllowedDir",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return asTSharkStatusFromPayload(payload);
    },
    async allowToolDir(tool, dir) {
      if (!desktopApp.AllowToolDir) {
        throw missingTypedBindingError("DesktopApp.AllowToolDir");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.AllowToolDir!(tool, dir), {
        endpoint: "DesktopApp.AllowToolDir",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "desktop-ipc");
    },
    async listToolAllowedDirs(tool) {
      if (!desktopApp.ListToolAllowedDirs) {
        throw missingTypedBindingError("DesktopApp.ListToolAllowedDirs");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.ListToolAllowedDirs!(tool), {
        endpoint: "DesktopApp.ListToolAllowedDirs",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return dirsFromPayload(payload);
    },
    async removeToolAllowedDir(tool, dir) {
      if (!desktopApp.RemoveToolAllowedDir) {
        throw missingTypedBindingError("DesktopApp.RemoveToolAllowedDir");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.RemoveToolAllowedDir!(tool, dir), {
        endpoint: "DesktopApp.RemoveToolAllowedDir",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "desktop-ipc");
    },
    async getMCPStatus(signal?: AbortSignal) {
      return await resolveMCPThroughDesktopIPC({
        signal,
        desktopMethod: desktopApp.GetMCPStatus,
        desktopMethodName: "DesktopApp.GetMCPStatus",
      });
    },
    async updateMCPConfig(config: MCPConfig, signal?: AbortSignal) {
      return await resolveMCPThroughDesktopIPC({
        signal,
        desktopMethod: desktopApp.UpdateMCPConfig
          ? () => desktopApp.UpdateMCPConfig!({ enabled: config.enabled })
          : undefined,
        desktopMethodName: "DesktopApp.UpdateMCPConfig",
      });
    },
    async startStreamingPackets(filePath: string, filter: string, signal?: AbortSignal) {
      if (!desktopApp.StartCapture) {
        throw missingTypedBindingError("DesktopApp.StartCapture");
      }
      await withDesktopIpcControls(() => desktopApp.StartCapture!(filePath, filter), {
        endpoint: "DesktopApp.StartCapture",
        responseKind: "typed-ipc",
        signal,
        timeoutMs: START_CAPTURE_IPC_TIMEOUT_MS,
      });
    },
    async stopStreamingPackets() {
      if (!desktopApp.StopCapture) {
        throw missingTypedBindingError("DesktopApp.StopCapture");
      }
      await withDesktopIpcControls(() => desktopApp.StopCapture!(), {
        endpoint: "DesktopApp.StopCapture",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async prepareCaptureReplacement() {
      if (!desktopApp.PrepareCaptureReplacement) {
        throw missingTypedBindingError("DesktopApp.PrepareCaptureReplacement");
      }
      await withDesktopIpcControls(() => desktopApp.PrepareCaptureReplacement!(), {
        endpoint: "DesktopApp.PrepareCaptureReplacement",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async closeCapture() {
      if (!desktopApp.CloseCapture) {
        throw missingTypedBindingError("DesktopApp.CloseCapture");
      }
      await withDesktopIpcControls(() => desktopApp.CloseCapture!(), {
        endpoint: "DesktopApp.CloseCapture",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async getCaptureStatus(signal?: AbortSignal) {
      if (!desktopApp.GetCaptureStatus) {
        throw missingTypedBindingError("DesktopApp.GetCaptureStatus");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.GetCaptureStatus!(), {
        endpoint: "DesktopApp.GetCaptureStatus",
        responseKind: "typed-ipc",
        signal,
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return withCaptureStatusMeta(asCaptureStatus(payload), "desktop-ipc");
    },
    async listPacketsPage(cursor: number, limit: number, filter = "", signal?: AbortSignal) {
      if (!desktopApp.ListPacketsPage) {
        throw missingTypedBindingError("DesktopApp.ListPacketsPage");
      }
      const payload = await withDesktopIpcControls(() => desktopApp.ListPacketsPage!(cursor, limit, filter), {
        endpoint: "DesktopApp.ListPacketsPage",
        responseKind: "typed-ipc",
        signal,
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return withPacketsPageMeta(asPacketsPageResult(payload), "desktop-ipc");
    },
    async getTLSConfig() {
      if (!desktopApp.GetTLSConfig) {
        throw missingTypedBindingError("DesktopApp.GetTLSConfig");
      }
      return asDecryptionConfig(
        await withDesktopIpcControls(() => desktopApp.GetTLSConfig!(), {
          endpoint: "DesktopApp.GetTLSConfig",
          responseKind: "typed-ipc",
          timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
        }),
      );
    },
    async updateTLSConfig(cfg: DecryptionConfig) {
      if (!desktopApp.UpdateTLSConfig) {
        throw missingTypedBindingError("DesktopApp.UpdateTLSConfig");
      }
      await withDesktopIpcControls(() => desktopApp.UpdateTLSConfig!(toDecryptionConfigRequest(cfg)), {
        endpoint: "DesktopApp.UpdateTLSConfig",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
  };

  return new Proxy(bridge, {
    get(target, property, receiver) {
      if (property in target) {
        return Reflect.get(target, property, receiver);
      }
      return Reflect.get(missingBindingBridge as unknown as Record<PropertyKey, unknown>, property, receiver);
    },
  }) as BackendBridge;
}

function asTSharkStatusFromPayload(payload: unknown): TSharkStatus {
  return asTSharkStatus(asPlainObject(payload) ?? {});
}

function dirsFromPayload(payload: unknown): string[] {
  const dirs = asPlainObject(payload)?.dirs;
  if (!Array.isArray(dirs)) {
    return [];
  }
  return dirs.map((dir) => String(dir ?? "")).filter((dir) => dir.length > 0);
}

async function resolveMCPThroughDesktopIPC({
  signal,
  desktopMethod,
  desktopMethodName,
}: {
  signal?: AbortSignal;
  desktopMethod?: () => Promise<unknown>;
  desktopMethodName: string;
}): Promise<MCPStatus> {
  if (!desktopMethod) {
    throw missingTypedBindingError(desktopMethodName);
  }
  const payload = await withDesktopIpcControls(desktopMethod, {
    endpoint: desktopMethodName,
    responseKind: "typed-ipc",
    signal,
    timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
  });
  return asMCPStatus((asPlainObject(payload) ?? {}) as MCPStatusWireDTO);
}

function missingTypedBindingError(endpoint: string): DesktopIpcRequestError {
  return new DesktopIpcRequestError(
    "typed_binding_required",
    `Wails desktop build requires typed IPC binding: ${endpoint}. Regenerate Wails bindings and retry.`,
    endpoint,
    0,
  );
}

function runtimeSnapshotMethod(
  desktopApp: DesktopTransportBinding,
  mode: string,
): (() => Promise<unknown>) | undefined {
  if (mode === "fast") {
    return desktopApp.GetToolRuntimeSnapshotFast ?? desktopApp.GetToolRuntimeSnapshot;
  }
  return desktopApp.GetToolRuntimeSnapshotFull ?? desktopApp.GetToolRuntimeSnapshot;
}

function runtimeConfigUpdateMethod(
  desktopApp: DesktopTransportBinding,
  mode: string,
): ((config: unknown) => Promise<unknown>) | undefined {
  if (mode === "fast") {
    return desktopApp.UpdateToolRuntimeConfigFast ?? desktopApp.UpdateToolRuntimeConfig;
  }
  return desktopApp.UpdateToolRuntimeConfigFull ?? desktopApp.UpdateToolRuntimeConfig;
}

function toToolRuntimeRequest(config: ToolRuntimeConfig) {
  return {
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
  };
}
