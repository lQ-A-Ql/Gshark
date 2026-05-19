import { useCallback, useEffect, useMemo, useState } from "react";
import type { USBAnalysis as USBAnalysisData, USBHIDSourceMode } from "../../core/types";
import { EMPTY_INVESTIGATION_REPORT } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { backendClients } from "../../integrations/backendClients";

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
const usbAnalysisCache = new Map<string, USBAnalysisData>();

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
  const [analysis, setAnalysis] = useState<USBAnalysisData>(EMPTY_USB_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const refreshAnalysis = useCallback(
    (force = false) => {
      if (!backendConnected) {
        cancelAnalysisRequest();
        setLoading(false);
        setError("");
        setAnalysis(EMPTY_USB_ANALYSIS);
        return;
      }
      if (!force && cacheKey && usbAnalysisCache.has(cacheKey)) {
        cancelAnalysisRequest();
        setAnalysis(readUSBAnalysisCache(cacheKey) ?? EMPTY_USB_ANALYSIS);
        setLoading(false);
        setError("");
        return;
      }
      setLoading(true);
      setError("");
      return runAnalysisRequest({
        request: (signal) => backendClients.analysis.getUSBAnalysis(signal, hidSource, hidEventLimit),
        onSuccess: (payload) => {
          if (cacheKey) {
            writeUSBAnalysisCache(cacheKey, payload);
          }
          setAnalysis(payload);
        },
        onError: (err) => {
          setError(err instanceof Error ? err.message : "USB 分析加载失败");
          setAnalysis(EMPTY_USB_ANALYSIS);
        },
        onSettled: () => setLoading(false),
      });
    },
    [backendConnected, cacheKey, cancelAnalysisRequest, hidEventLimit, hidSource, runAnalysisRequest],
  );

  useEffect(() => {
    if (isPreloadingCapture) return;
    return refreshAnalysis();
  }, [isPreloadingCapture, refreshAnalysis]);

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
  const cached = usbAnalysisCache.get(cacheKey);
  if (!cached) return undefined;
  usbAnalysisCache.delete(cacheKey);
  usbAnalysisCache.set(cacheKey, cached);
  return cached;
}

export function writeUSBAnalysisCache(cacheKey: string, payload: USBAnalysisData) {
  if (usbAnalysisCache.has(cacheKey)) {
    usbAnalysisCache.delete(cacheKey);
  }
  usbAnalysisCache.set(cacheKey, payload);
  while (usbAnalysisCache.size > USB_ANALYSIS_CACHE_CAPACITY) {
    const oldestKey = usbAnalysisCache.keys().next().value as string | undefined;
    if (!oldestKey) break;
    usbAnalysisCache.delete(oldestKey);
  }
}

export function clearUSBAnalysisCacheForTest() {
  usbAnalysisCache.clear();
}
