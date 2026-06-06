import { useCallback, useEffect, useRef } from "react";
import { useBackend } from "../state/contexts/BackendContext";
import { useCapture } from "../state/contexts/CaptureContext";
import { usePacket } from "../state/contexts/PacketContext";
import { PRELOAD_BUDGET } from "./preloadBudget";
import { scheduleRouteHeavyWarmup } from "./heavyWarmupPreload";

export function useRouteHeavyWarmupIntent(currentPathname: string) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { backendConnected } = useBackend();
  const { fileMeta, captureRevision, isPreloadingCapture } = useCapture();
  const { totalPackets } = usePacket();

  const cancelHeavyWarmupIntent = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const scheduleHeavyWarmupIntent = useCallback((routePath: string) => {
    cancelHeavyWarmupIntent();
    timerRef.current = setTimeout(() => {
      timerRef.current = null;
      void scheduleRouteHeavyWarmup(routePath, "hover", {
        backendConnected,
        captureReady: Boolean(fileMeta.path) && !isPreloadingCapture,
        filePath: fileMeta.path,
        totalPackets,
        captureRevision,
        currentRouteIdle: currentPathname !== routePath,
      });
    }, PRELOAD_BUDGET.heavyHoverIntentDelayMs);
  }, [backendConnected, cancelHeavyWarmupIntent, captureRevision, currentPathname, fileMeta.path, isPreloadingCapture, totalPackets]);

  useEffect(() => cancelHeavyWarmupIntent, [cancelHeavyWarmupIntent]);

  return { scheduleHeavyWarmupIntent, cancelHeavyWarmupIntent };
}
