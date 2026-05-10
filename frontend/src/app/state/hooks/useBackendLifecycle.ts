import {
  type Dispatch,
  useCallback,
  useEffect,
  useRef,
  useState,
  type MutableRefObject,
  type SetStateAction,
} from "react";
import type { DecryptionConfig, ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import { bridge, type TSharkStatus } from "../../integrations/wailsBridge";
import {
  type MediaAnalysisProgress,
  type ThreatAnalysisProgress,
} from "./useAnalysisProgress";
import { useToolRuntime } from "./useToolRuntime";
import { createBackendLifecycleEventHandlers } from "./backendLifecycleEvents";
import { getBackendUnavailableStatus, loadStartupTLSConfig, loadStartupToolRuntime } from "./backendLifecycleStartup";
import { clearWindowTimer } from "./backendLifecycleTimers";
import { wakeCaptureWaiters as wakeCaptureWaitersUtil } from "../captureSignal";

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

  const wakeCaptureWaiters = useCallback(() => {
    wakeCaptureWaitersUtil(captureWaitersRef.current);
  }, [captureWaitersRef]);

  const setTSharkPath = useCallback(
    async (path: string) => {
      await setTSharkPathImpl(path, backendConnected, setBackendStatus);
    },
    [backendConnected, setTSharkPathImpl],
  );

  const refreshToolRuntimeSnapshot = useCallback(async () => {
    return await refreshToolRuntimeSnapshotImpl(backendConnected);
  }, [backendConnected, refreshToolRuntimeSnapshotImpl]);

  const saveToolRuntimeConfig = useCallback(
    async (patch: Partial<ToolRuntimeConfig>) => {
      return await saveToolRuntimeConfigImpl(patch, backendConnected, setBackendStatus);
    },
    [backendConnected, saveToolRuntimeConfigImpl],
  );

  const updateDecryptionConfig = useCallback(
    (patch: Partial<DecryptionConfig>) => {
      setDecryptionConfig((prev) => {
        const next = { ...prev, ...patch };
        if (backendConnected) {
          void bridge.updateTLSConfig(next).catch(() => setBackendStatus("TLS 配置更新失败"));
        }
        return next;
      });
    },
    [backendConnected],
  );

  useEffect(
    () => () => {
      clearWindowTimer(refreshTimerRef);
      clearWindowTimer(backendRetryTimerRef);
    },
    [],
  );

  useEffect(() => {
    let dispose: (() => void) | null = null;
    let cancelled = false;

    const clearBackendRetryTimer = () => clearWindowTimer(backendRetryTimerRef);

    const scheduleBackendRetry = (delayMs = 2000) => {
      clearBackendRetryTimer();
      backendRetryTimerRef.current = window.setTimeout(() => {
        void setup();
      }, delayMs);
    };

    const setup = async () => {
      if (cancelled) return;
      const available = await bridge.isAvailable();
      if (cancelled) return;
      if (!available) {
        setBackendConnected(false);
        setBackendStatus(await getBackendUnavailableStatus());
        scheduleBackendRetry();
        return;
      }

      clearBackendRetryTimer();
      setBackendConnected(true);
      setBackendStatus("后端已连接，等待打开文件");

      await loadStartupToolRuntime({
        isCancelled: () => cancelled,
        setBackendStatus,
        setIsTSharkChecking,
        setIsToolRuntimeLoading,
        setToolRuntimeCheckDegraded,
        setToolRuntimeSnapshot,
        setTsharkStatus,
      });
      await loadStartupTLSConfig(setDecryptionConfig, setBackendStatus);

      dispose = bridge.subscribeEvents(
        createBackendLifecycleEventHandlers({
          activeCapturePathRef,
          parseFinishedRef,
          parseErrorRef,
          preloadingRef,
          refreshTimerRef,
          scheduleLoadMoreRef,
          refreshAnalysisResultRef,
          updateProgressFromStatusRef,
          wakeCaptureWaiters,
          setSelectedPacketId,
          setMediaAnalysisProgress,
          setThreatAnalysisProgress,
          setIsThreatAnalysisLoading,
          setBackendStatus,
        }),
      );
    };

    void setup();

    return () => {
      cancelled = true;
      clearBackendRetryTimer();
      if (dispose) dispose();
      clearWindowTimer(refreshTimerRef);
    };
  }, [
    activeCapturePathRef,
    captureWaitersRef,
    parseErrorRef,
    parseFinishedRef,
    preloadingRef,
    refreshAnalysisResultRef,
    scheduleLoadMoreRef,
    setIsThreatAnalysisLoading,
    setMediaAnalysisProgress,
    setSelectedPacketId,
    setThreatAnalysisProgress,
    updateProgressFromStatusRef,
    wakeCaptureWaiters,
  ]);

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
