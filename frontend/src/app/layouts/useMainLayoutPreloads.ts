import { useEffect, useRef } from "react";
import { PRELOAD_BUDGET } from "../preload/preloadBudget";
import { cancelCapturePreloads } from "../preload/preloadScheduler";
import { preloadRouteModule } from "../preload/routePreload";
import { scheduleRouteLightDataPreload } from "../preload/preloadTargetRunners";
import { NAV_ITEMS } from "./mainLayoutConfig";

export function useMainLayoutPreloads({
  backendConnected,
  captureRevision,
  filePath,
  isPreloadingCapture,
  pathname,
  totalPackets,
}: {
  backendConnected: boolean;
  captureRevision: number;
  filePath: string;
  isPreloadingCapture: boolean;
  pathname: string;
  totalPackets: number;
}) {
  useIdleNeighborRoutePreload(pathname);
  useCapturePreloadCancellation(captureRevision, filePath, totalPackets);

  useEffect(() => {
    if (!backendConnected || isPreloadingCapture || !filePath) return;
    void scheduleRouteLightDataPreload(pathname, "route-enter", {
      backendConnected,
      filePath,
      totalPackets,
      captureRevision,
    });
  }, [backendConnected, captureRevision, filePath, isPreloadingCapture, pathname, totalPackets]);
}

function useIdleNeighborRoutePreload(pathname: string) {
  useEffect(() => {
    const timer = setTimeout(() => {
      const index = NAV_ITEMS.findIndex((item) => item.path === pathname);
      const nextPath = NAV_ITEMS[index + 1]?.path ?? NAV_ITEMS[index - 1]?.path;
      if (nextPath) void preloadRouteModule(nextPath, "idle");
    }, PRELOAD_BUDGET.idleDelayMs);
    return () => clearTimeout(timer);
  }, [pathname]);
}

function useCapturePreloadCancellation(captureRevision: number, filePath: string, totalPackets: number) {
  const previousKeyRef = useRef("");
  const captureKey = filePath ? `${captureRevision}::${filePath}::${totalPackets}` : "";

  useEffect(() => {
    const previous = previousKeyRef.current;
    if (previous && previous !== captureKey) cancelCapturePreloads(previous);
    previousKeyRef.current = captureKey;
  }, [captureKey]);
}
