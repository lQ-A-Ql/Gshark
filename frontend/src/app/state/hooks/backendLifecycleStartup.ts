import { backendClients } from "../../integrations/backendClients";
import { withAbortableTimeout } from "../../utils/asyncControl";
import { STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "../captureConstants";
import { detectToolRuntimeProbeTransport } from "../toolRuntimeProbeState";
import { readToolRuntimeConfigState, writeObservedToolRuntimeSnapshotConfig } from "../toolRuntimeStorage";
import {
  applyStartupRuntimeSnapshot,
  loadFullToolRuntimeInBackground,
  markRuntimeProbeFailure,
  startupToolRuntimeConfigForSync,
  syncSavedToolRuntimeConfig,
  toolRuntimeConfigsEqual,
} from "./backendLifecycleToolRuntimeStartup";
import type { StartupToolRuntimeOptions } from "./backendLifecycleStartupTypes";

export async function loadStartupToolRuntime(options: StartupToolRuntimeOptions) {
  const {
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
  } = options;
  setIsTSharkChecking(true);
  setIsToolRuntimeLoading(true);
  setToolRuntimeCheckDegraded(false);
  setToolRuntimeProbeState("probing_fast");
  setToolRuntimeProbeTransport(detectToolRuntimeProbeTransport());
  setLastToolRuntimeProbeError("");

  let isSyncingSavedConfig = false;
  try {
    const savedState = readToolRuntimeConfigState();
    const snapshot = await withAbortableTimeout(
      (signal) => backendClients.runtime.getToolRuntimeSnapshot(signal, "fast"),
      STARTUP_TOOL_RUNTIME_TIMEOUT_MS,
      "startup fast tool runtime check timed out",
    );
    setToolRuntimeProbeTransport(snapshot.transport ?? detectToolRuntimeProbeTransport());
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
    if (!isCancelled() && !shouldSyncSavedConfig) {
      writeObservedToolRuntimeSnapshotConfig(snapshot.config);
      void loadFullToolRuntimeInBackground(options);
    }

    if (!isCancelled() && shouldSyncSavedConfig) {
      isSyncingSavedConfig = true;
      void syncSavedToolRuntimeConfig({
        ...options,
        explicitFields: savedState.explicitFields,
        savedConfig: syncConfig,
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
