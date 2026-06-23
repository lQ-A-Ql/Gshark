import type { DecryptionConfig, MCPConfig, MCPStatus, SpeechToTextStatus, ToolRuntimeConfig } from "../core/types";
import {
  asCaptureStatus,
  asPacketsPageResult,
  withCaptureStatusMeta,
  withPacketsPageMeta,
} from "./clients/captureClient";
import type { FFmpegStatus, TSharkStatus } from "./clients/toolRuntimeClient";
import { asToolRuntimeSnapshot } from "./mappers/runtimeMapper";
import { asMCPStatus } from "./mappers/mcpStatusMapper";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./mappers/tlsMapper";
import { withToolRuntimeSnapshotMeta } from "./toolRuntimeSnapshotMeta";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { createBackendBridgeFromTransport } from "./backendBridgeTransport";
import { createTypedDesktopOverrides } from "./desktopTypedBridge";
import { createDisabledGenericIpcBackendTransport } from "./desktopDisabledGenericIpcTransport";
import { withDesktopIpcControls } from "./desktopIpcControls";
import { isLegacyDesktopGenericIpcDisableExperimentEnabled } from "./desktopGenericIpcPolicy";
import { asPlainObject } from "./mappers/mapperPrimitives";
import type { MCPStatusWireDTO } from "./wire/mcpWireDtos";

export { resolveDesktopGenericIpcPolicy } from "./desktopGenericIpcPolicy";

interface DesktopBridgeContext {
  desktopApp: DesktopTransportBinding;
  fallbackBridge: BackendBridge;
}

const FAST_RUNTIME_IPC_TIMEOUT_MS = 2000;
const DEFAULT_TYPED_IPC_TIMEOUT_MS = 10000;
const START_CAPTURE_IPC_TIMEOUT_MS = 15000;

export function createDesktopBridge({ desktopApp, fallbackBridge }: DesktopBridgeContext): BackendBridge {
  // isDesktopGenericIpcDisabled is now always true for the removed generic adapter path.
  const disabledTransport = createDisabledGenericIpcBackendTransport();
  const dataBridge = createBackendBridgeFromTransport({
    requestJSON: disabledTransport.requestJSON,
    requestBlob: disabledTransport.requestBlob,
    requestText: disabledTransport.requestText,
    subscribeEvents: disabledTransport.subscribeEvents,
    getDesktopAppBinding: () => desktopApp,
  });

  return {
    ...dataBridge,
    ...createTypedDesktopOverrides(desktopApp),
    async isAvailable() {
      if (desktopApp.IsBackendReady) {
        const backendReady = await desktopApp.IsBackendReady();
        if (!backendReady) {
          return false;
        }
      }
      if (desktopApp.PingBackendDataPlane) {
        const probe = await desktopApp.PingBackendDataPlane();
        return Boolean((probe as { ready?: unknown })?.ready);
      }
      return await fallbackBridge.isAvailable();
    },
    async getDesktopBackendStatus() {
      if (!desktopApp.BackendStatus) {
        return await fallbackBridge.getDesktopBackendStatus();
      }
      return String(await desktopApp.BackendStatus()).trim();
    },
    async getToolRuntimeSnapshot(signal?: AbortSignal, mode = "full") {
      const ipcSnapshot = runtimeSnapshotMethod(desktopApp, mode);
      if (!ipcSnapshot) {
        return await fallbackBridge.getToolRuntimeSnapshot(signal, mode);
      }
      try {
        const payload = await withDesktopIpcControls(ipcSnapshot, {
          endpoint: `DesktopApp.GetToolRuntimeSnapshot(${mode})`,
          responseKind: "typed-ipc",
          signal,
          timeoutMs: mode === "fast" ? FAST_RUNTIME_IPC_TIMEOUT_MS : DEFAULT_TYPED_IPC_TIMEOUT_MS,
        });
        return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "desktop-ipc");
      } catch (error) {
        const fallbackSnapshot = await fallbackBridge.getToolRuntimeSnapshot(signal, mode);
        return withToolRuntimeSnapshotMeta(
          fallbackSnapshot,
          "http-fallback",
          desktopIpcErrorMessage(error, "Wails IPC 运行时组件探测失败"),
        );
      }
    },
    async checkTShark(): Promise<TSharkStatus> {
      try {
        const snapshot = await this.getToolRuntimeSnapshot();
        return { ...snapshot.tshark, customPath: snapshot.tshark.customPath ?? "" };
      } catch {
        return { available: false, path: "", message: "tshark 状态探测失败", customPath: "", usingCustomPath: false };
      }
    },
    async checkFFmpeg(): Promise<FFmpegStatus> {
      try {
        const snapshot = await this.getToolRuntimeSnapshot();
        return snapshot.ffmpeg;
      } catch {
        return { available: false, path: "", message: "ffmpeg 状态探测失败" };
      }
    },
    async checkSpeechToText(): Promise<SpeechToTextStatus> {
      try {
        const snapshot = await this.getToolRuntimeSnapshot();
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
          message: "语音转写状态探测失败",
        };
      }
    },
    async updateToolRuntimeConfig(config: ToolRuntimeConfig, signal?: AbortSignal, mode = "full") {
      const ipcUpdate = runtimeConfigUpdateMethod(desktopApp, mode);
      if (!ipcUpdate) {
        return await fallbackBridge.updateToolRuntimeConfig(config, signal, mode);
      }
      try {
        const payload = await withDesktopIpcControls(() => ipcUpdate(toToolRuntimeRequest(config)), {
          endpoint: `DesktopApp.UpdateToolRuntimeConfig(${mode})`,
          responseKind: "typed-ipc",
          signal,
          timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
        });
        return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "desktop-ipc");
      } catch (error) {
        const fallbackSnapshot = await fallbackBridge.updateToolRuntimeConfig(config, signal, mode);
        const message = error instanceof Error ? error.message : "Wails IPC 运行时组件配置同步失败";
        return withToolRuntimeSnapshotMeta(fallbackSnapshot, "http-fallback", message);
      }
    },
    async setTSharkPath(path: string): Promise<TSharkStatus> {
      if (!desktopApp.SetTSharkPath) {
        return await fallbackBridge.setTSharkPath(path);
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
      return await fallbackBridge.allowTSharkDir(dir);
    },
    async listTSharkAllowedDirs(): Promise<string[]> {
      return await fallbackBridge.listTSharkAllowedDirs();
    },
    async removeTSharkAllowedDir(dir: string): Promise<TSharkStatus> {
      return await fallbackBridge.removeTSharkAllowedDir(dir);
    },
    async allowToolDir(tool, dir) {
      return await fallbackBridge.allowToolDir(tool, dir);
    },
    async listToolAllowedDirs(tool) {
      return await fallbackBridge.listToolAllowedDirs(tool);
    },
    async removeToolAllowedDir(tool, dir) {
      return await fallbackBridge.removeToolAllowedDir(tool, dir);
    },
    async getMCPStatus(signal?: AbortSignal) {
      return await resolveMCPThroughDesktopIPC({
        signal,
        desktopMethod: desktopApp.GetMCPStatus,
        desktopMethodName: "DesktopApp.GetMCPStatus",
        fallback: () => fallbackBridge.getMCPStatus(signal),
      });
    },
    async updateMCPConfig(config: MCPConfig, signal?: AbortSignal) {
      return await resolveMCPThroughDesktopIPC({
        signal,
        desktopMethod: desktopApp.UpdateMCPConfig
          ? () => desktopApp.UpdateMCPConfig!({ enabled: config.enabled })
          : undefined,
        desktopMethodName: "DesktopApp.UpdateMCPConfig",
        fallback: () => fallbackBridge.updateMCPConfig(config, signal),
      });
    },
    async startStreamingPackets(filePath: string, filter: string, signal?: AbortSignal) {
      if (!desktopApp.StartCapture) {
        return signal
          ? await fallbackBridge.startStreamingPackets(filePath, filter, signal)
          : await fallbackBridge.startStreamingPackets(filePath, filter);
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
        return await fallbackBridge.stopStreamingPackets();
      }
      await withDesktopIpcControls(() => desktopApp.StopCapture!(), {
        endpoint: "DesktopApp.StopCapture",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async prepareCaptureReplacement() {
      if (!desktopApp.PrepareCaptureReplacement) {
        return await fallbackBridge.prepareCaptureReplacement();
      }
      await withDesktopIpcControls(() => desktopApp.PrepareCaptureReplacement!(), {
        endpoint: "DesktopApp.PrepareCaptureReplacement",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async closeCapture() {
      if (!desktopApp.CloseCapture) {
        return await fallbackBridge.closeCapture();
      }
      await withDesktopIpcControls(() => desktopApp.CloseCapture!(), {
        endpoint: "DesktopApp.CloseCapture",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async getCaptureStatus(signal?: AbortSignal) {
      if (!desktopApp.GetCaptureStatus) {
        return await fallbackBridge.getCaptureStatus(signal);
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
        return signal
          ? await dataBridge.listPacketsPage(cursor, limit, filter, signal)
          : await dataBridge.listPacketsPage(cursor, limit, filter);
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
        return await fallbackBridge.getTLSConfig();
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
        return await fallbackBridge.updateTLSConfig(cfg);
      }
      await withDesktopIpcControls(() => desktopApp.UpdateTLSConfig!(toDecryptionConfigRequest(cfg)), {
        endpoint: "DesktopApp.UpdateTLSConfig",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
  };
}

export function isDesktopGenericIpcDisableExperimentEnabled(): boolean {
  // VITE_DESKTOP_DISABLE_GENERIC_IPC remains the legacy Round 20 experiment alias.
  // VITE_DESKTOP_GENERIC_IPC_POLICY=compat remains recognizable but no longer enables the removed adapter path.
  return isLegacyDesktopGenericIpcDisableExperimentEnabled();
}

function desktopIpcErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  if (typeof error === "string" && error.trim()) {
    return error.trim();
  }
  return fallback;
}

async function resolveMCPThroughDesktopIPC({
  signal,
  desktopMethod,
  desktopMethodName,
  fallback,
}: {
  signal?: AbortSignal;
  desktopMethod?: () => Promise<unknown>;
  desktopMethodName: string;
  fallback: () => Promise<MCPStatus>;
}): Promise<MCPStatus> {
  if (!desktopMethod) {
    return await fallback();
  }
  try {
    const payload = await withDesktopIpcControls(desktopMethod, {
      endpoint: desktopMethodName,
      responseKind: "typed-ipc",
      signal,
      timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
    });
    return asMCPStatus((asPlainObject(payload) ?? {}) as MCPStatusWireDTO);
  } catch {
    return await fallback();
  }
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
