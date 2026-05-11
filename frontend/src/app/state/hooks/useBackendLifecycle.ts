import {
  type Dispatch,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type MutableRefObject,
  type SetStateAction,
} from "react";
import type { DecryptionConfig, ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import type { TSharkStatus } from "../../integrations/wailsBridge";
import {
  type MediaAnalysisProgress,
  type ThreatAnalysisProgress,
} from "./useAnalysisProgress";
import { useToolRuntime } from "./useToolRuntime";
import { loadStartupTLSConfig } from "./backendLifecycleStartup";
import { clearWindowTimer } from "./backendLifecycleTimers";
import { useBackendLifecycleControls } from "./useBackendLifecycleControls";
import { useBackendLifecycleStartupEffect } from "./useBackendLifecycleStartupEffect";

interface UseBackendLifecycleOptions {
  readonly activeCapturePathRef: MutableRefObject<string>;
  readonly captureWaitersRef: MutableRefObject<Set<() => void>>;
  readonly parseFinishedRef: MutableRefObject<boolean>;
  readonly parseErrorRef: MutableRefObject<string>;
  readonly preloadingRef: MutableRefObject<boolean>;
  readonly scheduleLoadMoreRef: MutableRefObject<() => void>;
  readonly refreshAnalysisResultRef: MutableRefObject<
    (options?: { capturePath?: string; quietSuccess?: boolean }) => Promise<void>
  >;
  readonly updateProgressFromStatusRef: MutableRefObject<(message: string) => boolean>;
  readonly setSelectedPacketId: Dispatch<SetStateAction<number | null>>;
  readonly setMediaAnalysisProgress: Dispatch<SetStateAction<MediaAnalysisProgress>>;
  readonly setThreatAnalysisProgress: Dispatch<SetStateAction<ThreatAnalysisProgress>>;
  readonly setIsThreatAnalysisLoading: Dispatch<SetStateAction<boolean>>;
}

export interface BackendLifecycleState {
  backendConnected: boolean;
  backendStatus: string;
  setBackendStatus: Dispatch<SetStateAction<string>>;
  decryptionConfig: DecryptionConfig;
  updateDecryptionConfig: (patch: Partial<DecryptionConfig>) => void;
  tsharkStatus: TSharkStatus;
  isTSharkChecking: boolean;
  toolRuntimeCheckDegraded: boolean;
  setTSharkPath: (path: string) => Promise<void>;
  toolRuntimeSnapshot: ToolRuntimeSnapshot | null;
  isToolRuntimeLoading: boolean;
  refreshToolRuntimeSnapshot: () => Promise<ToolRuntimeSnapshot | null>;
  saveToolRuntimeConfig: (patch: Partial<ToolRuntimeConfig>) => Promise<ToolRuntimeSnapshot>;
}

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
    setTSharkPath: setTSharkPathImpl,
    refreshToolRuntimeSnapshot: refreshToolRuntimeSnapshotImpl,
    saveToolRuntimeConfig: saveToolRuntimeConfigImpl,
  } = useToolRuntime();
  const [backendConnected, setBackendConnected] = useState(false);
  const [backendStatus, setBackendStatus] = useState("等待后端连接");
  const [decryptionConfig, setDecryptionConfig] = useState<DecryptionConfig>({
    sslKeyLogPath: "",
    privateKeyPath: "",
    privateKeyIpPort: "",
  });

  const refreshTimerRef = useRef<number | null>(null);
  const backendRetryTimerRef = useRef<number | null>(null);

  const { setTSharkPath, refreshToolRuntimeSnapshot, saveToolRuntimeConfig, updateDecryptionConfig } =
    useBackendLifecycleControls({
      backendConnected,
      setBackendStatus,
      setDecryptionConfig,
      setTSharkPathImpl,
      refreshToolRuntimeSnapshotImpl,
      saveToolRuntimeConfigImpl,
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
    }),
    [
      setBackendStatus,
      setIsTSharkChecking,
      setIsToolRuntimeLoading,
      setToolRuntimeCheckDegraded,
      setToolRuntimeSnapshot,
      setTsharkStatus,
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
    setTSharkPath,
    toolRuntimeSnapshot,
    isToolRuntimeLoading,
    refreshToolRuntimeSnapshot,
    saveToolRuntimeConfig,
  };
}
