import { useMemo } from "react";
import type { DBCProfile, VehicleAnalysis as VehicleAnalysisData } from "../../core/types";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";

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
  report: EMPTY_INVESTIGATION_REPORT,
};

const vehicleAnalysisCache = createAnalysisResourceCache<VehicleAnalysisData>();

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
  const cacheKey = useMemo(
    () => buildVehicleAnalysisCacheKey(captureRevision, filePath, totalPackets, dbcProfiles),
    [captureRevision, dbcProfiles, filePath, totalPackets],
  );
  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data: analysis, loading, error, refresh: refreshAnalysis } = useAnalysisResult<VehicleAnalysisData>({
    cache: vehicleAnalysisCache,
    cacheKey,
    emptyValue: EMPTY_VEHICLE_ANALYSIS,
    enabled,
    isPreloadingCapture,
    errorMessage: "车机分析加载失败",
    fetch: (signal) => backendClients.analysis.getVehicleAnalysis(signal),
  });

  return { analysis, loading, error, refreshAnalysis };
}

export function buildVehicleAnalysisCacheKey(
  captureRevision: number,
  filePath: string,
  totalPackets: number,
  dbcProfiles: DBCProfile[],
) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  const dbcKey = dbcProfiles
    .map((item) => item.path)
    .sort()
    .join("|");
  return `${captureRevision}::${normalizedPath}::${totalPackets}::${dbcKey}`;
}
