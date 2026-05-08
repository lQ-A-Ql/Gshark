import {
  type Dispatch,
  useCallback,
  useEffect,
  useRef,
  useState,
  type MutableRefObject,
  type SetStateAction,
} from "react";
import type { DecryptionConfig, Packet, ToolRuntimeConfig, ToolRuntimeSnapshot } from "../../core/types";
import { bridge, type TSharkStatus } from "../../integrations/wailsBridge";
import { isOperationTimeoutError, withTimeout } from "../../utils/asyncControl";
import {
  EMPTY_MEDIA_ANALYSIS_PROGRESS,
  EMPTY_THREAT_ANALYSIS_PROGRESS,
  type MediaAnalysisProgress,
  type ThreatAnalysisProgress,
} from "./useAnalysisProgress";
import { useToolRuntime } from "./useToolRuntime";
import {
  isProgressStatusMessage,
  shouldIgnoreCaptureErrorWithoutActiveCapture,
  shouldIgnoreCaptureStatusWithoutActiveCapture,
  shouldMarkParseErrorFromStatus,
  shouldMarkParseFinishedFromStatus,
  shouldResetMediaAnalysisFromError,
  shouldResetMediaAnalysisFromStatus,
  shouldResetThreatAnalysisFromError,
  shouldResetThreatAnalysisFromStatus,
} from "../backendStatusMessage";
import { markCaptureParseFinished } from "../captureParseRuntimeState";
import { STARTUP_TLS_CONFIG_TIMEOUT_MS, STARTUP_TOOL_RUNTIME_TIMEOUT_MS } from "../captureConstants";
import { preserveSelectedPacketId } from "../selectedPacketState";
import { wakeCaptureWaiters as wakeCaptureWaitersUtil } from "../captureSignal";
import { readToolRuntimeConfig, writeToolRuntimeConfig } from "./useToolRuntime";

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
      if (refreshTimerRef.current != null) {
        window.clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
      if (backendRetryTimerRef.current != null) {
        window.clearTimeout(backendRetryTimerRef.current);
        backendRetryTimerRef.current = null;
      }
    },
    [],
  );

  useEffect(() => {
    let dispose: (() => void) | null = null;
    let cancelled = false;

    const clearBackendRetryTimer = () => {
      if (backendRetryTimerRef.current != null) {
        window.clearTimeout(backendRetryTimerRef.current);
        backendRetryTimerRef.current = null;
      }
    };

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
        const desktopStatus = await bridge.getDesktopBackendStatus().catch(() => "");
        const detail = desktopStatus.trim();
        if (detail && detail !== "not-started" && detail !== "starting") {
          setBackendStatus(detail);
        } else {
          setBackendStatus("桌面后端未连接，请启动或重启桌面应用");
        }
        scheduleBackendRetry();
        return;
      }

      clearBackendRetryTimer();
      setBackendConnected(true);
      setBackendStatus("后端已连接，等待打开文件");
      setIsTSharkChecking(true);
      setIsToolRuntimeLoading(true);
      setToolRuntimeCheckDegraded(false);

      try {
        const savedConfig = readToolRuntimeConfig();
        const snapshot = await withTimeout(
          bridge.updateToolRuntimeConfig(savedConfig),
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
        if (!cancelled) {
          writeToolRuntimeConfig(snapshot.config);
        }
        if (!cancelled && snapshot.tshark.available && snapshot.tshark.message && snapshot.tshark.message !== "ok") {
          setBackendStatus(snapshot.tshark.message);
        }
        if (!cancelled && !snapshot.tshark.available) {
          setBackendStatus(snapshot.tshark.message || "未检测到 tshark，请先配置路径");
        }
      } catch (error) {
        if (!cancelled) {
          setToolRuntimeCheckDegraded(true);
          const prefix = isOperationTimeoutError(error) ? "运行时组件检测超时" : "运行时组件检测失败";
          setBackendStatus(`${prefix}，已先进入主界面；可在设置侧栏刷新状态`);
          setTsharkStatus((prev) => ({
            ...prev,
            message: `${prefix}，请稍后在设置侧栏刷新状态`,
          }));
        }
      } finally {
        if (!cancelled) {
          setIsTSharkChecking(false);
          setIsToolRuntimeLoading(false);
        }
      }

      try {
        const tls = await withTimeout(
          bridge.getTLSConfig(),
          STARTUP_TLS_CONFIG_TIMEOUT_MS,
          "startup TLS config check timed out",
        );
        if (tls) {
          setDecryptionConfig(tls);
        }
      } catch (error) {
        if (!isOperationTimeoutError(error)) {
          setBackendStatus("后端初始化失败");
        }
      }

      dispose = bridge.subscribeEvents({
        packet: (packet: Packet) => {
          setSelectedPacketId((prev) => preserveSelectedPacketId(prev, packet.id));
          if (preloadingRef.current) {
            return;
          }
          scheduleLoadMoreRef.current();

          if (refreshTimerRef.current != null) {
            window.clearTimeout(refreshTimerRef.current);
          }
          refreshTimerRef.current = window.setTimeout(() => {
            void refreshAnalysisResultRef.current();
          }, 500);
        },
        status: (message) => {
          const msg = message || "后端运行中";
          if (shouldIgnoreCaptureStatusWithoutActiveCapture(msg, Boolean(activeCapturePathRef.current))) {
            return;
          }
          if (isProgressStatusMessage(msg)) {
            updateProgressFromStatusRef.current(msg);
            wakeCaptureWaiters();
            return;
          }
          if (shouldMarkParseFinishedFromStatus(msg)) {
            markCaptureParseFinished({
              parseFinishedRef,
              parseErrorRef,
              errorMessage: shouldMarkParseErrorFromStatus(msg) ? msg : undefined,
            });
          }
          if (shouldResetMediaAnalysisFromStatus(msg)) {
            setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
          }
          if (shouldResetThreatAnalysisFromStatus(msg)) {
            setThreatAnalysisProgress((prev) => (prev.phase === "complete" ? prev : EMPTY_THREAT_ANALYSIS_PROGRESS));
          }
          wakeCaptureWaiters();
          setBackendStatus(msg);
        },
        error: (message) => {
          const next = message || "后端事件异常";
          if (shouldIgnoreCaptureErrorWithoutActiveCapture(next, Boolean(activeCapturePathRef.current))) {
            return;
          }
          if (preloadingRef.current) {
            markCaptureParseFinished({
              parseFinishedRef,
              parseErrorRef,
              errorMessage: next,
            });
          }
          if (shouldResetMediaAnalysisFromError(next)) {
            setMediaAnalysisProgress(EMPTY_MEDIA_ANALYSIS_PROGRESS);
          }
          if (shouldResetThreatAnalysisFromError(next)) {
            setThreatAnalysisProgress(EMPTY_THREAT_ANALYSIS_PROGRESS);
            setIsThreatAnalysisLoading(false);
          }
          wakeCaptureWaiters();
          setBackendStatus(next);
        },
      });
    };

    void setup();

    return () => {
      cancelled = true;
      clearBackendRetryTimer();
      if (dispose) dispose();
      if (refreshTimerRef.current != null) {
        window.clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
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
