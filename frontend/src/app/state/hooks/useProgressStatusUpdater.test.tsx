import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it } from "vitest";
import { EMPTY_MEDIA_ANALYSIS_PROGRESS, EMPTY_THREAT_ANALYSIS_PROGRESS } from "./useAnalysisProgress";
import { useProgressStatusUpdater } from "./useProgressStatusUpdater";

describe("useProgressStatusUpdater", () => {
  it("updates capture and analysis progress from backend status messages", () => {
    const { result } = renderHook(() => {
      const preloadProcessedRef = useRef(0);
      const preloadTotalRef = useRef(0);
      const [preloadProcessed, setPreloadProcessed] = useState(0);
      const [preloadTotal, setPreloadTotal] = useState(0);
      const [totalPackets, setTotalPackets] = useState(0);
      const [mediaProgress, setMediaAnalysisProgress] = useState(EMPTY_MEDIA_ANALYSIS_PROGRESS);
      const [threatProgress, setThreatAnalysisProgress] = useState(EMPTY_THREAT_ANALYSIS_PROGRESS);
      const updateProgressFromStatus = useProgressStatusUpdater({
        preloadProcessedRef,
        preloadTotalRef,
        setPreloadProcessed,
        setPreloadTotal,
        setTotalPackets,
        setMediaAnalysisProgress,
        setThreatAnalysisProgress,
      });
      return {
        mediaProgress,
        preloadProcessed,
        preloadProcessedRef,
        preloadTotal,
        preloadTotalRef,
        threatProgress,
        totalPackets,
        updateProgressFromStatus,
      };
    });

    act(() => {
      expect(result.current.updateProgressFromStatus("__progress__:loading:4:9")).toBe(true);
      expect(result.current.updateProgressFromStatus("__progress__:media:2:5:转写媒体")).toBe(true);
      expect(result.current.updateProgressFromStatus("__progress__:threat:3:6:扫描流")).toBe(true);
    });

    expect(result.current.preloadProcessed).toBe(4);
    expect(result.current.preloadProcessedRef.current).toBe(4);
    expect(result.current.preloadTotal).toBe(9);
    expect(result.current.preloadTotalRef.current).toBe(9);
    expect(result.current.totalPackets).toBe(9);
    expect(result.current.mediaProgress.label).toBe("转写媒体");
    expect(result.current.threatProgress.label).toBe("扫描流");
  });
});
