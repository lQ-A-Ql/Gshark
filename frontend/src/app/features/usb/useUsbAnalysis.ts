import { useCallback, useEffect, useMemo, useState } from "react";
import type { USBAnalysis as USBAnalysisData } from "../../core/types";
import { useAbortableRequest } from "../../hooks/useAbortableRequest";
import { bridge } from "../../integrations/wailsBridge";

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
  hid: { keyboardEvents: [], mouseEvents: [], devices: [], notes: [] },
  massStorage: { totalPackets: 0, readPackets: 0, writePackets: 0, controlPackets: 0, devices: [], luns: [], commands: [], readOperations: [], writeOperations: [], notes: [] },
  other: { totalPackets: 0, controlPackets: 0, devices: [], endpoints: [], setupRequests: [], controlRecords: [], records: [], notes: [] },
  notes: [],
};

const usbAnalysisCache = new Map<string, USBAnalysisData>();

export interface UseUsbAnalysisOptions {
  backendConnected: boolean;
  isPreloadingCapture: boolean;
  filePath: string;
  totalPackets: number;
  captureRevision: number;
}

export function useUsbAnalysis({
  backendConnected,
  isPreloadingCapture,
  filePath,
  totalPackets,
  captureRevision,
}: UseUsbAnalysisOptions) {
  const cacheKey = useMemo(() => buildUSBAnalysisCacheKey(captureRevision, filePath, totalPackets), [captureRevision, filePath, totalPackets]);
  const [analysis, setAnalysis] = useState<USBAnalysisData>(EMPTY_USB_ANALYSIS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const { run: runAnalysisRequest, cancel: cancelAnalysisRequest } = useAbortableRequest();

  const refreshAnalysis = useCallback((force = false) => {
    if (!backendConnected) {
      cancelAnalysisRequest();
      setLoading(false);
      setError("");
      setAnalysis(EMPTY_USB_ANALYSIS);
      return;
    }
    if (!force && cacheKey && usbAnalysisCache.has(cacheKey)) {
      cancelAnalysisRequest();
      setAnalysis(usbAnalysisCache.get(cacheKey) ?? EMPTY_USB_ANALYSIS);
      setLoading(false);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    return runAnalysisRequest({
      request: (signal) => bridge.getUSBAnalysis(signal),
      onSuccess: (payload) => {
        if (cacheKey) {
          usbAnalysisCache.set(cacheKey, payload);
        }
        setAnalysis(payload);
      },
      onError: (err) => {
        setError(err instanceof Error ? err.message : "USB 分析加载失败");
        setAnalysis(EMPTY_USB_ANALYSIS);
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

export function buildUSBAnalysisCacheKey(captureRevision: number, filePath: string, totalPackets: number) {
  const normalizedPath = filePath.trim();
  if (!normalizedPath) return "";
  return `${captureRevision}::${normalizedPath}::${totalPackets}`;
}
