import type { DecryptionConfig, ToolRuntimeConfig } from "../core/types";
import {
  asCaptureStatus,
  asPacketsPageResult,
  withCaptureStatusMeta,
  withPacketsPageMeta,
} from "./clients/captureClient";
import type { TSharkStatus } from "./clients/toolRuntimeClient";
import { asToolRuntimeSnapshot } from "./mappers/runtimeMapper";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./mappers/tlsMapper";
import { withToolRuntimeSnapshotMeta } from "./toolRuntimeSnapshotMeta";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

interface DesktopBridgeContext {
  desktopApp: DesktopTransportBinding;
  fallbackBridge: BackendBridge;
}

const FAST_RUNTIME_IPC_TIMEOUT_MS = 2000;

export function createDesktopBridge({ desktopApp, fallbackBridge }: DesktopBridgeContext): BackendBridge {
  return {
    ...fallbackBridge,
    async isAvailable() {
      if (desktopApp.IsBackendReady) {
        return await desktopApp.IsBackendReady();
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
        const payload =
          mode === "fast" ? await withIpcTimeout(ipcSnapshot(), FAST_RUNTIME_IPC_TIMEOUT_MS) : await ipcSnapshot();
        return withToolRuntimeSnapshotMeta(asToolRuntimeSnapshot(payload), "desktop-ipc");
      } catch (error) {
        const fallbackSnapshot = await fallbackBridge.getToolRuntimeSnapshot(signal, mode);
        const message = error instanceof Error ? error.message : "Wails IPC 运行时组件探测失败";
        return withToolRuntimeSnapshotMeta(fallbackSnapshot, "http-fallback", message);
      }
    },
    async updateToolRuntimeConfig(config: ToolRuntimeConfig, signal?: AbortSignal, mode = "full") {
      const ipcUpdate = runtimeConfigUpdateMethod(desktopApp, mode);
      if (!ipcUpdate) {
        return await fallbackBridge.updateToolRuntimeConfig(config, signal, mode);
      }
      try {
        const payload =
          mode === "fast"
            ? await withIpcTimeout(ipcUpdate(toToolRuntimeRequest(config)), FAST_RUNTIME_IPC_TIMEOUT_MS)
            : await ipcUpdate(toToolRuntimeRequest(config));
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
      const payload = await desktopApp.SetTSharkPath(path);
      return {
        available: Boolean((payload as any)?.available),
        path: String((payload as any)?.path ?? ""),
        message: String((payload as any)?.message ?? ""),
        customPath: String((payload as any)?.custom_path ?? ""),
        usingCustomPath: Boolean((payload as any)?.using_custom_path),
      };
    },
    async startStreamingPackets(filePath: string, filter: string) {
      if (!desktopApp.StartCapture) {
        return await fallbackBridge.startStreamingPackets(filePath, filter);
      }
      await desktopApp.StartCapture(filePath, filter);
    },
    async stopStreamingPackets() {
      if (!desktopApp.StopCapture) {
        return await fallbackBridge.stopStreamingPackets();
      }
      await desktopApp.StopCapture();
    },
    async prepareCaptureReplacement() {
      if (!desktopApp.PrepareCaptureReplacement) {
        return await fallbackBridge.prepareCaptureReplacement();
      }
      await desktopApp.PrepareCaptureReplacement();
    },
    async closeCapture() {
      if (!desktopApp.CloseCapture) {
        return await fallbackBridge.closeCapture();
      }
      await desktopApp.CloseCapture();
    },
    async getCaptureStatus() {
      if (!desktopApp.GetCaptureStatus) {
        return await fallbackBridge.getCaptureStatus();
      }
      try {
        return withCaptureStatusMeta(asCaptureStatus(await desktopApp.GetCaptureStatus()), "desktop-ipc");
      } catch (error) {
        const fallbackStatus = await fallbackBridge.getCaptureStatus();
        const message = error instanceof Error ? error.message : "Wails IPC 状态确认失败";
        return withCaptureStatusMeta(fallbackStatus, "http-fallback", message);
      }
    },
    async listPacketsPage(cursor: number, limit: number, filter = "", signal?: AbortSignal) {
      if (!desktopApp.ListPacketsPage) {
        return signal
          ? await fallbackBridge.listPacketsPage(cursor, limit, filter, signal)
          : await fallbackBridge.listPacketsPage(cursor, limit, filter);
      }
      try {
        return withPacketsPageMeta(
          asPacketsPageResult(await desktopApp.ListPacketsPage(cursor, limit, filter)),
          "desktop-ipc",
        );
      } catch (error) {
        const fallbackPage = signal
          ? await fallbackBridge.listPacketsPage(cursor, limit, filter, signal)
          : await fallbackBridge.listPacketsPage(cursor, limit, filter);
        const message = error instanceof Error ? error.message : "Wails IPC 数据页确认失败";
        return withPacketsPageMeta(fallbackPage, "http-fallback", message);
      }
    },
    async getTLSConfig() {
      if (!desktopApp.GetTLSConfig) {
        return await fallbackBridge.getTLSConfig();
      }
      return asDecryptionConfig(await desktopApp.GetTLSConfig());
    },
    async updateTLSConfig(cfg: DecryptionConfig) {
      if (!desktopApp.UpdateTLSConfig) {
        return await fallbackBridge.updateTLSConfig(cfg);
      }
      await desktopApp.UpdateTLSConfig(toDecryptionConfigRequest(cfg));
    },
  };
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

function withIpcTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Wails IPC 快速探测超时（${timeoutMs}ms）`)), timeoutMs);
  });
  return Promise.race([operation, timeout]).finally(() => {
    if (timer !== undefined) window.clearTimeout(timer);
  });
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
