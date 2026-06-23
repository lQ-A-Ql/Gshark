import { useMemo } from "react";
import type { USBAnalysis as USBAnalysisData, USBHIDSourceMode } from "../../core/types";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";
import { backendClients } from "../../integrations/backendClients";
import { createAnalysisResourceCache } from "../../core/analysisResourceCache";
import { hasUsableCapturePath } from "../../core/usableCapture";
import { useAnalysisResult } from "../../hooks/useAnalysisResult";

export const EMPTY_USB_ANALYSIS: USBAnalysisData = {
  totalUSBPackets: 0,
  keyboardPackets: 0,
  mousePackets: 0,
  otherUSBPackets: 0,
  hidPackets: 0,
  massStoragePackets: 0,
  protocols: [],
  transferTypes: [],
  directions: [],
  devices: [],
  endpoints: [],
  setupRequests: [],
  records: [],
  keyboardEvents: [],
  mouseEvents: [],
  otherRecords: [],
  hidSourceMode: "auto",
  hidSourceCandidates: [],
  hidSelectedSource: undefined,
  hidSourceNotes: [],
  hidEventLimit: 0,
  hidEventsTruncated: false,
  hidMouseEventsTotal: 0,
  hidKeyboardEventsTotal: 0,
  hid: { keyboardEvents: [], mouseEvents: [], devices: [], notes: [] },
  massStorage: {
    totalPackets: 0,
    readPackets: 0,
    writePackets: 0,
    controlPackets: 0,
    devices: [],
    luns: [],
    commands: [],
    readOperations: [],
    writeOperations: [],
    notes: [],
  },
  other: {
    totalPackets: 0,
    controlPackets: 0,
    devices: [],
    endpoints: [],
    setupRequests: [],
    controlRecords: [],
    records: [],
    notes: [],
  },
  notes: [],
  report: EMPTY_INVESTIGATION_REPORT,
};

const USB_ANALYSIS_CACHE_CAPACITY = 5;
const usbAnalysisCache = createAnalysisResourceCache<USBAnalysisData>({ capacity: USB_ANALYSIS_CACHE_CAPACITY });

export interface UseUsbAnalysisOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
  hidSource?: USBHIDSourceMode;
  hidEventLimit?: number;
}

export function useUsbAnalysis({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
  hidSource = "auto",
  hidEventLimit = 20000,
}: UseUsbAnalysisOptions) {
  const cacheKey = useMemo(
    () => buildUSBAnalysisCacheKey(captureRevision, filePath, totalPackets, hidSource, hidEventLimit),
    [captureRevision, filePath, hidEventLimit, hidSource, totalPackets],
  );
  const enabled = backendConnected && hasUsableCapturePath(filePath, totalPackets);

  const { data: analysis, loading, error, refresh: refreshAnalysis } = useAnalysisResult<USBAnalysisData>({
    cache: usbAnalysisCache,
    cacheKey,
    emptyValue: EMPTY_USB_ANALYSIS,
    enabled,
    isPreloadingCapture,
    errorMessage: "USB 分析加载失败",
    fetch: (signal) => backendClients.analysis.getUSBAnalysis(signal, hidSource, hidEventLimit),
  });

  return { analysis, loading, error, refreshAnalysis };
}

export function buildUSBAnalysisCacheKey(
  captureRevision: number,
  filePath: string,
  totalPackets: number,
  hidSource: USBHIDSourceMode = "auto",
  hidEventLimit = 20000,
) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}::${hidSource}::${hidEventLimit}`;
}

export function readUSBAnalysisCache(cacheKey: string) {
  return usbAnalysisCache.get(cacheKey);
}

export function writeUSBAnalysisCache(cacheKey: string, payload: USBAnalysisData) {
  usbAnalysisCache.set(cacheKey, payload);
}

export function clearUSBAnalysisCacheForTest() {
  usbAnalysisCache.clear();
}
