import { useCallback, useEffect, useMemo, useState } from "react";
import type { DBCProfile, VehicleAnalysis as VehicleAnalysisData } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { bridge } from "../../integrations/wailsBridge";

export const EMPTY_VEHICLE_ANALYSIS: VehicleAnalysisData = {
  totalVehiclePackets: 0,
  protocols: [],
  conversations: [],
  can: {
    totalFrames: 0,
    extendedFrames: 0,
    rtrFrames: 0,
    errorFrames: 0,
    busIds: [],
    messageIds: [],
    payloadProtocols: [],
    payloadRecords: [],
    dbcProfiles: [],
    decodedMessageDist: [],
    decodedSignals: [],
    decodedMessages: [],
    signalTimelines: [],
    frames: [],
  },
  j1939: { totalMessages: 0, pgns: [], sourceAddrs: [], targetAddrs: [], messages: [] },
  doip: { totalMessages: 0, messageTypes: [], vins: [], endpoints: [], messages: [] },
  uds: { totalMessages: 0, serviceIDs: [], negativeCodes: [], dtcs: [], vins: [], messages: [], transactions: [] },
  recommendations: [],
};

const vehicleAnalysisCache = new Map<string, VehicleAnalysisData>();

export interface UseVehicleAnalysisOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
  dbcProfiles: DBCProfile[];
}

export function useVehicleAnalysis({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
  dbcProfiles,
}: UseVehicleAnalysisOptions) {
  const cacheKey = useMemo(() => buildVehicleAnalysisCacheKey(captureRevision, filePath, totalPackets, dbcProfiles), [captureRevision, dbcProfiles, filePath, totalPackets]);
  const [analysis, setAnalysis] = useState<VehicleAnalysisData>(EMPTY_VEHICLE_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      cancelAnalysisRequest();
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_VEHICLE_ANALYSIS);
      return;
    }
    if (!force && cacheKey && vehicleAnalysisCache.has(cacheKey)) {
      cancelAnalysisRequest();
      setAnalysis(vehicleAnalysisCache.get(cacheKey) ?? EMPTY_VEHICLE_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    return runAnalysisRequest({
      request: (signal) => bridge.getVehicleAnalysis(signal),
      onSuccess: (payload) => {
        if (cacheKey) {
          vehicleAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      },
      onError: (err) => {
        setError(err instanceof Error ? err.message : "车机分析加载失败");
        setAnalysis(EMPTY_VEHICLE_ANALYSIS);
      },
      onSettled: () => setLoading(false),
    });
  }, [backendConnected, cacheKey, cancelAnalysisRequest, runAnalysisRequest]);

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

  return { analysis, loading, error, refreshAnalysis };
}

export function buildVehicleAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number, dbcProfiles: DBCProfile[]) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  const dbcKey = dbcProfiles.map((item) => item.path).sort().join("|");
  return `${captureRevision}::${normalizedPath}::${totalPackets}::${dbcKey}`;
}
