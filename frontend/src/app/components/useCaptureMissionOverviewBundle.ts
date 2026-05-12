import { useEffect, useState } from "react";

import type { GlobalTrafficStats, IndustrialAnalysis, MediaAnalysis, USBAnalysis, VehicleAnalysis } from "../core/types";
import { backendClients } from "../integrations/backendClients";

export interface CaptureMissionOverviewBundle {
  stats: GlobalTrafficStats | null;
  industrial: IndustrialAnalysis | null;
  vehicle: VehicleAnalysis | null;
  media: MediaAnalysis | null;
  usb: USBAnalysis | null;
}

interface UseCaptureMissionOverviewBundleOptions {
  backendConnected: boolean;
  captureKey: string;
  isPreloadingCapture: boolean;
}

const overviewCache = new Map<string, CaptureMissionOverviewBundle>();

export function useCaptureMissionOverviewBundle({
  backendConnected,
  captureKey,
  isPreloadingCapture,
}: UseCaptureMissionOverviewBundleOptions) {
  const [overviewBundle, setOverviewBundle] = useState<CaptureMissionOverviewBundle | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(false);

  useEffect(() => {
    if (!backendConnected || !captureKey || isPreloadingCapture) {
      setOverviewBundle(null);
      setOverviewLoading(false);
      return;
    }

    if (overviewCache.has(captureKey)) {
      setOverviewBundle(overviewCache.get(captureKey) ?? null);
      setOverviewLoading(false);
      return;
    }

    let cancelled = false;
    const abortController = new AbortController();
    setOverviewLoading(true);
    void Promise.all([
      backendClients.analysis.getGlobalTrafficStats(abortController.signal).catch(() => null),
      backendClients.analysis.getIndustrialAnalysis(abortController.signal).catch(() => null),
      backendClients.analysis.getVehicleAnalysis(abortController.signal).catch(() => null),
      backendClients.media.getMediaAnalysis(false, abortController.signal).catch(() => null),
      backendClients.analysis.getUSBAnalysis(abortController.signal).catch(() => null),
    ])
      .then(([stats, industrial, vehicle, media, usb]) => {
        if (cancelled) return;
        const next = { stats, industrial, vehicle, media, usb };
        overviewCache.set(captureKey, next);
        setOverviewBundle(next);
      })
      .finally(() => {
        if (!cancelled) {
          setOverviewLoading(false);
        }
      });

    return () => {
      cancelled = true;
      abortController.abort();
    };
  }, [backendConnected, captureKey, isPreloadingCapture]);

  return { overviewBundle, overviewLoading };
}
