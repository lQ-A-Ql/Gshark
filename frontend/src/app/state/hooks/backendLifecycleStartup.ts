import type { Dispatch, SetStateAction } from "react";
import type { ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/clients/toolRuntimeClient";
import { backendClients } from "../../integrations/backendClients";
import { isOperationTimeoutError, withAbortableTimeout } from "../../utils/asyncControl";
import { STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "../captureConstants";
import { readToolRuntimeConfigState, writeObservedToolRuntimeSnapshotConfig } from "../toolRuntimeStorage";
import {
  applyStartupRuntimeSnapshot,
  startupToolRuntimeConfigForSync,
  syncSavedToolRuntimeConfig,
  toolRuntimeConfigsEqual,
} from "./backendLifecycleToolRuntimeStartup";

export async function getBackendUnavailableStatus() {
  const desktopStatus = await backendClients.runtime.getDesktopBackendStatus().catch(() => "");
  const detail = desktopStatus.trim();
  return detail && detail !== "not-started" && detail !== "starting" ? detail : "桌面后端未连接，请启动或重启桌面应用";
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

  let isSyncingSavedConfig = false;
  try {
    const savedState = readToolRuntimeConfigState();
    const snapshot = await withAbortableTimeout(
      (signal) => backendClients.runtime.getToolRuntimeSnapshot(signal),
      STARTUP_TOOL_RUNTIME_TIMEOUT_MS,
      "startup tool runtime check timed out",
    );
    const syncConfig = startupToolRuntimeConfigForSync(savedState, snapshot.config);
    const shouldSyncSavedConfig = syncConfig !== null && !toolRuntimeConfigsEqual(syncConfig, snapshot.config);
    applyStartupRuntimeSnapshot({
      isCancelled,
      setBackendStatus,
      setToolRuntimeSnapshot,
      setTsharkStatus,
      snapshot,
    });
    if (!isCancelled() && !shouldSyncSavedConfig) writeObservedToolRuntimeSnapshotConfig(snapshot.config);

    if (!isCancelled() && shouldSyncSavedConfig) {
      isSyncingSavedConfig = true;
      void syncSavedToolRuntimeConfig({
        explicitFields: savedState.explicitFields,
        isCancelled,
        savedConfig: syncConfig,
        setBackendStatus,
        setIsToolRuntimeLoading,
        setToolRuntimeCheckDegraded,
        setToolRuntimeSnapshot,
        setTsharkStatus,
      });
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
      if (!isSyncingSavedConfig) {
        setIsToolRuntimeLoading(false);
      }
    }
  }
}
