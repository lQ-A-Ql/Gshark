import { createContext, useContext, type PropsWithChildren } from "react";
import type { ExtractedObject, ThreatHit } from "../../core/types";
import type { MediaAnalysisProgress, ThreatAnalysisProgress } from "../hooks/useAnalysisProgress";

export interface AnalysisContextValue {
  threatHits: ThreatHit[];
  isThreatAnalysisLoading: boolean;
  threatAnalysisProgress: ThreatAnalysisProgress;
  extractedObjects: ExtractedObject[];
  mediaAnalysisProgress: MediaAnalysisProgress;
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null);

export function AnalysisProvider({ children, value }: PropsWithChildren<{ value: AnalysisContextValue }>) {
  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>;
}

export function useAnalysis() {
  const ctx = useContext(AnalysisContext);
  if (!ctx) {
    throw new Error("useAnalysis must be used inside AnalysisProvider");
  }
  return ctx;
}
