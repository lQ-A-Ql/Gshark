import type { DecryptionConfig, ToolRuntimeConfig } from "../core/types";
import { asCaptureStatus } from "./clients/captureClient";
import type { TSharkStatus } from "./clients/toolRuntimeClient";
import { asToolRuntimeSnapshot } from "./mappers/runtimeMapper";
import { asDecryptionConfig, toDecryptionConfigRequest } from "./mappers/tlsMapper";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

interface DesktopBridgeContext {
  desktopApp: DesktopTransportBinding;
  fallbackBridge: BackendBridge;
}

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
    async getToolRuntimeSnapshot() {
      if (!desktopApp.GetToolRuntimeSnapshot) {
        return await fallbackBridge.getToolRuntimeSnapshot();
      }
      return asToolRuntimeSnapshot(await desktopApp.GetToolRuntimeSnapshot());
    },
    async updateToolRuntimeConfig(config: ToolRuntimeConfig) {
      if (!desktopApp.UpdateToolRuntimeConfig) {
        return await fallbackBridge.updateToolRuntimeConfig(config);
      }
      return asToolRuntimeSnapshot(await desktopApp.UpdateToolRuntimeConfig(toToolRuntimeRequest(config)));
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
      return asCaptureStatus(await desktopApp.GetCaptureStatus());
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
