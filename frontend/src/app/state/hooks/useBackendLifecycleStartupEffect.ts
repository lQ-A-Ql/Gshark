import { useEffect, type MutableRefObject } from "react";
import { bridge } from "../../integrations/wailsBridge";
import { wakeCaptureWaiters as wakeCaptureWaitersUtil } from "../captureSignal";
import { getBackendUnavailableStatus, loadStartupToolRuntime } from "./backendLifecycleStartup";
import { clearWindowTimer } from "./backendLifecycleTimers";
import { createBackendLifecycleEventHandlers, type BackendLifecycleEventOptions } from "./backendLifecycleEvents";

interface UseBackendLifecycleStartupEffectOptions extends Omit<BackendLifecycleEventOptions, "wakeCaptureWaiters"> {
  readonly backendRetryTimerRef: MutableRefObject<number | null>;
  readonly captureWaitersRef: MutableRefObject<Set<() => void>>;
  readonly setBackendConnected: (connected: boolean) => void;
  readonly startupToolRuntimeOptions: Omit<Parameters<typeof loadStartupToolRuntime>[0], "isCancelled">;
  readonly loadStartupTLSConfig: () => Promise<void>;
}

export function useBackendLifecycleStartupEffect({
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
}: UseBackendLifecycleStartupEffectOptions) {
  useEffect(() => {
    let dispose: (() => void) | null = null;
    let cancelled = false;
    const wakeCaptureWaiters = () => wakeCaptureWaitersUtil(captureWaitersRef.current);
    const clearBackendRetryTimer = () => clearWindowTimer(backendRetryTimerRef);
    const scheduleBackendRetry = (delayMs = 2000) => {
      clearBackendRetryTimer();
      backendRetryTimerRef.current = window.setTimeout(() => void setup(), delayMs);
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
      await loadStartupToolRuntime({ ...startupToolRuntimeOptions, isCancelled: () => cancelled });
      await loadTLSConfig();
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
    backendRetryTimerRef,
    captureWaitersRef,
    loadTLSConfig,
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
  ]);
}
