import type { Dispatch, SetStateAction } from "react";
import type { DecryptionConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import { backendClients } from "../../integrations/backendClients";
import { isOperationTimeoutError, withTimeout } from "../../utils/asyncControl";
import { STARTUP_TLS_CONFIG_TIMEOUT_MS, STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "../captureConstants";
import { readToolRuntimeConfig, writeToolRuntimeConfig } from "./useToolRuntime";

export async function getBackendUnavailableStatus() {
  const desktopStatus = await backendClients.runtime.getDesktopBackendStatus().catch(() => "");
  const detail = desktopStatus.trim();
  return detail && detail !== "not-started" && detail !== "starting"
    ? detail
    : "桌面后端未连接，请启动或重启桌面应用";
}

interface StartupToolRuntimeOptions {
  readonly isCancelled: () => boolean;
  readonly setBackendStatus: Dispatch<SetStateAction<string>>;
  readonly setIsTSharkChecking: Dispatch<SetStateAction<boolean>>;
  readonly setIsToolRuntimeLoading: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeCheckDegraded: Dispatch<SetStateAction<boolean>>;
  readonly setToolRuntimeSnapshot: Dispatch<SetStateAction<ToolRuntimeSnapshot | null>>;
  readonly setTsharkStatus: Dispatch<SetStateAction<TSharkStatus>>;
}

export async function loadStartupToolRuntime({
  isCancelled,
  setBackendStatus,
  setIsTSharkChecking,
  setIsToolRuntimeLoading,
  setToolRuntimeCheckDegraded,
  setToolRuntimeSnapshot,
  setTsharkStatus,
}: StartupToolRuntimeOptions) {
  setIsTSharkChecking(true);
  setIsToolRuntimeLoading(true);
  setToolRuntimeCheckDegraded(false);

  try {
    const savedConfig = readToolRuntimeConfig();
    const snapshot = await withTimeout(
      backendClients.runtime.updateToolRuntimeConfig(savedConfig),
      STARTUP_TOOL_RUNTIME_TIMEOUT_MS,
      "startup tool runtime check timed out",
    );
    setToolRuntimeSnapshot(snapshot);
    setTsharkStatus({
      available: snapshot.tshark.available,
      path: snapshot.tshark.path,
      message: snapshot.tshark.message,
      customPath: snapshot.tshark.customPath ?? "",
      usingCustomPath: snapshot.tshark.usingCustomPath,
    });
    if (!isCancelled()) writeToolRuntimeConfig(snapshot.config);
    if (!isCancelled() && snapshot.tshark.available && snapshot.tshark.message && snapshot.tshark.message !== "ok") {
      setBackendStatus(snapshot.tshark.message);
    }
    if (!isCancelled() && !snapshot.tshark.available) {
      setBackendStatus(snapshot.tshark.message || "未检测到 tshark，请先配置路径");
    }
  } catch (error) {
    if (!isCancelled()) {
      const prefix = isOperationTimeoutError(error) ? "运行时组件检测超时" : "运行时组件检测失败";
      setToolRuntimeCheckDegraded(true);
      setBackendStatus(`${prefix}，已先进入主界面；可在设置侧栏刷新状态`);
      setTsharkStatus((prev) => ({
        ...prev,
        message: `${prefix}，请稍后在设置侧栏刷新状态`,
      }));
    }
  } finally {
    if (!isCancelled()) {
      setIsTSharkChecking(false);
      setIsToolRuntimeLoading(false);
    }
  }
}

export async function loadStartupTLSConfig(
  setDecryptionConfig: Dispatch<SetStateAction<DecryptionConfig>>,
  setBackendStatus: Dispatch<SetStateAction<string>>,
) {
  try {
    const tls = await withTimeout(
      backendClients.securityMaterial.getTLSConfig(),
      STARTUP_TLS_CONFIG_TIMEOUT_MS,
      "startup TLS config check timed out",
    );
    if (tls) setDecryptionConfig(tls);
  } catch (error) {
    if (!isOperationTimeoutError(error)) {
      setBackendStatus("后端初始化失败");
    }
  }
}
