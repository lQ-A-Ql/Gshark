import { createContext, useContext, type PropsWithChildren } from "react";
import type { RecentCapture } from "../../core/types";
import type { CaptureFileMeta } from "../captureOpenState";
import type { CapturePreloadDiagnostics } from "../capturePreloadDiagnostics";
import type { CaptureTransactionStatus } from "../sentinelTypes";

export interface CaptureContextValue {
  isPreloadingCapture: boolean;
  preloadProcessed: number;
  preloadTotal: number;
  capturePreloadDiagnostics: CapturePreloadDiagnostics | null;
  captureTransaction: CaptureTransactionStatus;
  fileMeta: CaptureFileMeta;
  captureRevision: number;
  recentCaptures: RecentCapture[];
  openCapture: (filePath?: string) => Promise<boolean>;
  stopCapture: () => Promise<void>;
  retryCapturePreloadConfirm: () => Promise<boolean>;
}

const CaptureContext = createContext<CaptureContextValue | null>(null);

export function CaptureProvider({ children, value }: PropsWithChildren<{ value: CaptureContextValue }>) {
  return <CaptureContext.Provider value={value}>{children}</CaptureContext.Provider>;
}

export function useCapture() {
  const ctx = useContext(CaptureContext);
  if (!ctx) {
    throw new Error("useCapture must be used inside CaptureProvider");
  }
  return ctx;
}
