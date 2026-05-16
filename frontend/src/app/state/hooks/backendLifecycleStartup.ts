import { backendClients } from "../../integrations/backendClients";
import { withAbortableTimeout } from "../../utils/asyncControl";
import { STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "../captureConstants";
import { detectToolRuntimeProbeTransport } from "../toolRuntimeProbeState";
import { readToolRuntimeConfigState, writeObservedToolRuntimeSnapshotConfig } from "../toolRuntimeStorage";
import {
  applyStartupRuntimeSnapshot,
  markRuntimeProbeFailure,
  startupToolRuntimeConfigForSync,
  syncSavedToolRuntimeConfig,
  toolRuntimeConfigsEqual,
} from "./backendLifecycleToolRuntimeStartup";
import type { StartupToolRuntimeOptions } from "./backendLifecycleStartupTypes";

export async function loadStartupToolRuntime({
  isCancelled,
  setBackendStatus,
  setIsTSharkChecking,
  setIsToolRuntimeLoading,
  setToolRuntimeCheckDegraded,
  setToolRuntimeSnapshot,
  setTsharkStatus,
  setToolRuntimeProbeState,
  setToolRuntimeProbeTransport,
  setLastToolRuntimeProbeError,
}: StartupToolRuntimeOptions) {
  setIsTSharkChecking(true);
  setIsToolRuntimeLoading(true);
  setToolRuntimeCheckDegraded(false);
  setToolRuntimeProbeState("probing");
  setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
  setLastToolRuntimeProbeError("");

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
      setToolRuntimeProbeState,
      setLastToolRuntimeProbeError,
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
        setToolRuntimeProbeState,
        setToolRuntimeProbeTransport,
        setLastToolRuntimeProbeError,
      });
    }
  } catch (error) {
    markRuntimeProbeFailure({
      error,
      failurePrefix: "运行时组件检测失败",
      isCancelled,
      retryMessage: "已先进入主界面；可在设置侧栏刷新状态",
      setBackendStatus,
      setLastToolRuntimeProbeError,
      setToolRuntimeCheckDegraded,
      setToolRuntimeProbeState,
      setTsharkStatus,
      timeoutPrefix: "运行时组件检测超时",
    });
  } finally {
    if (!isCancelled()) {
      setIsTSharkChecking(false);
      if (!isSyncingSavedConfig) {
        setIsToolRuntimeLoading(false);
      }
    }
  }
}
