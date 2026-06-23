import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { DecryptionConfig, MCPStatus } from "../../core/types";
import { useToolRuntime } from "./useToolRuntime";
import { loadStartupTLSConfig } from "./backendLifecycleTLSStartup";
import { clearWindowTimer } from "./backendLifecycleTimers";
import { useBackendAuthToken } from "./useBackendAuthToken";
import type { BackendLifecycleState, UseBackendLifecycleOptions } from "./backendLifecycleTypes";
import { useBackendLifecycleControls } from "./useBackendLifecycleControls";
import { useBackendLifecycleMCPControls } from "./useBackendLifecycleMCPControls";
import { useBackendLifecycleStartupEffect } from "./useBackendLifecycleStartupEffect";

export function useBackendLifecycle({
  activeCapturePathRef,
  captureWaitersRef,
  parseFinishedRef,
  parseErrorRef,
  preloadingRef,
  scheduleLoadMoreRef,
  refreshAnalysisResultRef,
  updateProgressFromStatusRef,
  setSelectedPacketId,
  setMediaAnalysisProgress,
  setThreatAnalysisProgress,
  setIsThreatAnalysisLoading,
}: UseBackendLifecycleOptions): BackendLifecycleState {
  const {
    tsharkStatus,
    setTsharkStatus,
    isTSharkChecking,
    setIsTSharkChecking,
    toolRuntimeSnapshot,
    setToolRuntimeSnapshot,
    isToolRuntimeLoading,
    setIsToolRuntimeLoading,
    toolRuntimeCheckDegraded,
    setToolRuntimeCheckDegraded,
    toolRuntimeProbeState,
    setToolRuntimeProbeState,
    toolRuntimeProbeTransport,
    setToolRuntimeProbeTransport,
    lastToolRuntimeProbeError,
    setLastToolRuntimeProbeError,
    setTSharkPath: setTSharkPathImpl,
    allowTSharkDir: allowTSharkDirImpl,
    removeTSharkAllowedDir: removeTSharkAllowedDirImpl,
    refreshTSharkAllowedDirs: refreshTSharkAllowedDirsImpl,
    refreshToolRuntimeSnapshot: refreshToolRuntimeSnapshotImpl,
    saveToolRuntimeConfig: saveToolRuntimeConfigImpl,
  } = useToolRuntime();
  const [backendConnected, setBackendConnected] = useState(false);
  const [backendStatus, setBackendStatus] = useState("等待后端连接");
  const [mcpStatus, setMCPStatus] = useState<MCPStatus | null>(null);
  const [decryptionConfig, setDecryptionConfig] = useState<DecryptionConfig>({
    sslKeyLogPath: "",
    privateKeyPath: "",
    privateKeyIpPort: "",
  });

  const refreshTimerRef = useRef<number | null>(null);
  const backendRetryTimerRef = useRef<number | null>(null);
  const { backendAuthToken, isBackendAuthTokenLoading } = useBackendAuthToken(backendConnected);

  const { setTSharkPath, allowTSharkDir, removeTSharkAllowedDir, refreshTSharkAllowedDirs, refreshToolRuntimeSnapshot, saveToolRuntimeConfig, updateDecryptionConfig } =
    useBackendLifecycleControls({
      backendConnected,
      setBackendStatus,
      setDecryptionConfig,
      setTSharkPathImpl,
      allowTSharkDirImpl,
      removeTSharkAllowedDirImpl,
      refreshTSharkAllowedDirsImpl,
      refreshToolRuntimeSnapshotImpl,
      saveToolRuntimeConfigImpl,
    });
  const { refreshMCPStatus, saveMCPConfig } = useBackendLifecycleMCPControls({
    backendConnected,
    setMCPStatus,
  });
  const loadTLSConfig = useCallback(async () => {
    await loadStartupTLSConfig(setDecryptionConfig, setBackendStatus);
  }, []);
  const startupToolRuntimeOptions = useMemo(
    () => ({
      setBackendStatus,
      setIsTSharkChecking,
      setIsToolRuntimeLoading,
      setToolRuntimeCheckDegraded,
      setToolRuntimeSnapshot,
      setTsharkStatus,
      setToolRuntimeProbeState,
      setToolRuntimeProbeTransport,
      setLastToolRuntimeProbeError,
    }),
    [
      setBackendStatus,
      setIsTSharkChecking,
      setIsToolRuntimeLoading,
      setToolRuntimeCheckDegraded,
      setToolRuntimeSnapshot,
      setTsharkStatus,
      setToolRuntimeProbeState,
      setToolRuntimeProbeTransport,
      setLastToolRuntimeProbeError,
    ],
  );

  useEffect(
    () => () => {
      clearWindowTimer(refreshTimerRef);
      clearWindowTimer(backendRetryTimerRef);
    },
    [],
  );

  useBackendLifecycleStartupEffect({
    activeCapturePathRef,
    backendRetryTimerRef,
    captureWaitersRef,
    loadStartupTLSConfig: loadTLSConfig,
    parseErrorRef,
    parseFinishedRef,
    preloadingRef,
    refreshAnalysisResultRef,
    refreshTimerRef,
    scheduleLoadMoreRef,
    setBackendConnected,
    setBackendStatus,
    setMCPStatus,
    setIsThreatAnalysisLoading,
    setMediaAnalysisProgress,
    setSelectedPacketId,
    setThreatAnalysisProgress,
    startupToolRuntimeOptions,
    updateProgressFromStatusRef,
  });

  return {
    backendConnected,
    backendStatus,
    setBackendStatus,
    decryptionConfig,
    updateDecryptionConfig,
    tsharkStatus,
    isTSharkChecking,
    toolRuntimeCheckDegraded,
    toolRuntimeProbeState,
    toolRuntimeProbeTransport,
    lastToolRuntimeProbeError,
    setTSharkPath,
    allowTSharkDir,
    removeTSharkAllowedDir,
    refreshTSharkAllowedDirs,
    toolRuntimeSnapshot,
    isToolRuntimeLoading,
    refreshToolRuntimeSnapshot,
    saveToolRuntimeConfig,
    backendAuthToken,
    isBackendAuthTokenLoading,
    mcpStatus,
    refreshMCPStatus,
    saveMCPConfig,
  };
}
