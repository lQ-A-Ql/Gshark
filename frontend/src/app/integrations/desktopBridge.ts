import type { DecryptionConfig, MCPConfig, MCPStatus, ToolRuntimeConfig } from "../core/types";
import {
  asCaptureStatus,
  asPacketsPageResult,
  withCaptureStatusMeta,
  withPacketsPageMeta,
} from "./clients/captureClient";
import type { TSharkStatus } from "./clients/toolRuntimeClient";
import { asToolRuntimeSnapshot } from "./mappers/runtimeMapper";
import { asMCPStatus } from "./mappers/mcpStatusMapper";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./mappers/tlsMapper";
import { withToolRuntimeSnapshotMeta } from "./toolRuntimeSnapshotMeta";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";
import { createBackendBridgeFromTransport } from "./backendBridgeTransport";
import { createTypedDesktopOverrides } from "./desktopTypedBridge";
import {
  createDisabledGenericIpcBackendTransport,
  createIpcBackendTransport,
  withDesktopIpcControls,
} from "./ipcBackendTransport";
import {
  isDesktopGenericIpcDisabled,
  isLegacyDesktopGenericIpcDisableExperimentEnabled,
} from "./desktopGenericIpcPolicy";

export { resolveDesktopGenericIpcPolicy } from "./desktopGenericIpcPolicy";

interface DesktopBridgeContext {
  desktopApp: DesktopTransportBinding;
  fallbackBridge: BackendBridge;
}

const FAST_RUNTIME_IPC_TIMEOUT_MS = 2000;
const DEFAULT_TYPED_IPC_TIMEOUT_MS = 10000;
const START_CAPTURE_IPC_TIMEOUT_MS = 15000;

export function createDesktopBridge({ desktopApp, fallbackBridge }: DesktopBridgeContext): BackendBridge {
  const disableGenericIpc = isDesktopGenericIpcDisabled();
  const ipcTransport = disableGenericIpc
    ? createDisabledGenericIpcBackendTransport()
    : desktopApp.InvokeBackendJSON
      ? createIpcBackendTransport(desktopApp)
      : null;
  const dataBridge = ipcTransport
    ? createBackendBridgeFromTransport({
        requestJSON: ipcTransport.requestJSON,
        requestBlob: ipcTransport.requestBlob,
        requestText: ipcTransport.requestText,
        subscribeEvents: ipcTransport.subscribeEvents,
        getDesktopAppBinding: () => desktopApp,
      })
    : fallbackBridge;

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
      return await dataBridge.isAvailable();
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
        return await dataBridge.getToolRuntimeSnapshot(signal, mode);
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
        const fallbackSnapshot = await dataBridge.getToolRuntimeSnapshot(signal, mode);
        return withToolRuntimeSnapshotMeta(
          fallbackSnapshot,
          "http-fallback",
          desktopIpcErrorMessage(error, "Wails IPC 运行时组件探测失败"),
        );
      }
    },
    async updateToolRuntimeConfig(config: ToolRuntimeConfig, signal?: AbortSignal, mode = "full") {
      const ipcUpdate = runtimeConfigUpdateMethod(desktopApp, mode);
      if (!ipcUpdate) {
        return await dataBridge.updateToolRuntimeConfig(config, signal, mode);
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
        if (!ipcTransport) {
          const fallbackSnapshot = await fallbackBridge.updateToolRuntimeConfig(config, signal, mode);
          const message = error instanceof Error ? error.message : "Wails IPC 运行时组件配置同步失败";
          return withToolRuntimeSnapshotMeta(fallbackSnapshot, "http-fallback", message);
        }
        throw error;
      }
    },
    async setTSharkPath(path: string): Promise<TSharkStatus> {
      if (!desktopApp.SetTSharkPath) {
        return await dataBridge.setTSharkPath(path);
      }
      const payload = await withDesktopIpcControls(() => desktopApp.SetTSharkPath!(path), {
        endpoint: "DesktopApp.SetTSharkPath",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
      return {
        available: Boolean((payload as any)?.available),
        path: String((payload as any)?.path ?? ""),
        message: String((payload as any)?.message ?? ""),
        customPath: String((payload as any)?.custom_path ?? ""),
        usingCustomPath: Boolean((payload as any)?.using_custom_path),
      };
    },
    async getMCPStatus(signal?: AbortSignal) {
      return await resolveMCPThroughDesktopIPC({
        signal,
        desktopMethod: desktopApp.GetMCPStatus,
        desktopMethodName: "DesktopApp.GetMCPStatus",
        fallback: () => dataBridge.getMCPStatus(signal),
      });
    },
    async updateMCPConfig(config: MCPConfig, signal?: AbortSignal) {
      return await resolveMCPThroughDesktopIPC({
        signal,
        desktopMethod: desktopApp.UpdateMCPConfig
          ? () => desktopApp.UpdateMCPConfig!({ enabled: config.enabled })
          : undefined,
        desktopMethodName: "DesktopApp.UpdateMCPConfig",
        fallback: () => dataBridge.updateMCPConfig(config, signal),
      });
    },
    async startStreamingPackets(filePath: string, filter: string, signal?: AbortSignal) {
      if (!desktopApp.StartCapture) {
        return signal
          ? await dataBridge.startStreamingPackets(filePath, filter, signal)
          : await dataBridge.startStreamingPackets(filePath, filter);
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
        return await dataBridge.stopStreamingPackets();
      }
      await withDesktopIpcControls(() => desktopApp.StopCapture!(), {
        endpoint: "DesktopApp.StopCapture",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async prepareCaptureReplacement() {
      if (!desktopApp.PrepareCaptureReplacement) {
        return await dataBridge.prepareCaptureReplacement();
      }
      await withDesktopIpcControls(() => desktopApp.PrepareCaptureReplacement!(), {
        endpoint: "DesktopApp.PrepareCaptureReplacement",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async closeCapture() {
      if (!desktopApp.CloseCapture) {
        return await dataBridge.closeCapture();
      }
      await withDesktopIpcControls(() => desktopApp.CloseCapture!(), {
        endpoint: "DesktopApp.CloseCapture",
        responseKind: "typed-ipc",
        timeoutMs: DEFAULT_TYPED_IPC_TIMEOUT_MS,
      });
    },
    async getCaptureStatus(signal?: AbortSignal) {
      if (!desktopApp.GetCaptureStatus) {
        return await dataBridge.getCaptureStatus(signal);
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
        return await dataBridge.getTLSConfig();
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
        return await dataBridge.updateTLSConfig(cfg);
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
  // VITE_DESKTOP_GENERIC_IPC_POLICY is the Round 24 default-disabled policy and compat rollback switch.
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
    return asMCPStatus(payload as Record<string, unknown>);
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
    ffmpeg_path: config.ffmpegPath,
    python_path: config.pythonPath,
    vosk_model_path: config.voskModelPath,
    yara_enabled: config.yaraEnabled,
    yara_bin: config.yaraBin,
    yara_rules: config.yaraRules,
    yara_timeout_ms: config.yaraTimeoutMs,
  };
}
