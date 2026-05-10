import { describe, expect, it, vi } from "vitest";
import {
  EMPTY_MEDIA_ANALYSIS_PROGRESS,
  EMPTY_THREAT_ANALYSIS_PROGRESS,
  type MediaAnalysisProgress,
  type ThreatAnalysisProgress,
} from "./hooks/useAnalysisProgress";
import { updateProgressFromStatusState, type UpdateProgressFromStatusOptions } from "./progressStatusWorkflow";

function createOptions(message: string, overrides: Partial<UpdateProgressFromStatusOptions> = {}) {
  const preloadProcessedRef = { current: 11 };
  const preloadTotalRef = { current: 22 };
  let mediaProgress: MediaAnalysisProgress = { ...EMPTY_MEDIA_ANALYSIS_PROGRESS, recent: ["旧媒体"] };
  let threatProgress: ThreatAnalysisProgress = { ...EMPTY_THREAT_ANALYSIS_PROGRESS, recent: ["旧威胁"] };
  const options: UpdateProgressFromStatusOptions = {
    message,
    preloadProcessedRef,
    preloadTotalRef,
    setPreloadProcessed: vi.fn(),
    setPreloadTotal: vi.fn(),
    setTotalPackets: vi.fn(),
    setMediaAnalysisProgress: vi.fn((updater) => {
      mediaProgress = updater(mediaProgress);
    }),
    setThreatAnalysisProgress: vi.fn((updater) => {
      threatProgress = updater(threatProgress);
    }),
    ...overrides,
  };

  return {
    options,
    getMediaProgress: () => mediaProgress,
    getThreatProgress: () => threatProgress,
  };
}

describe("progressStatusWorkflow", () => {
  it("ignores non-progress status messages", () => {
    const { options } = createOptions("加载完成");

    expect(updateProgressFromStatusState(options)).toBe(false);
    expect(options.setPreloadProcessed).not.toHaveBeenCalled();
  });

  it("consumes malformed progress messages without mutating state", () => {
    const { options } = createOptions("__progress__:loading");

    expect(updateProgressFromStatusState(options)).toBe(true);
    expect(options.setPreloadProcessed).not.toHaveBeenCalled();
    expect(options.setMediaAnalysisProgress).not.toHaveBeenCalled();
  });

  it("updates media progress state and recent labels", () => {
    const { options, getMediaProgress } = createOptions("__progress__:media:2:4:扫描媒体对象");

    expect(updateProgressFromStatusState(options)).toBe(true);
    expect(getMediaProgress()).toMatchObject({
      active: true,
      current: 2,
      total: 4,
      label: "扫描媒体对象",
      phase: "scan",
      phaseLabel: "扫描中",
    });
    expect(getMediaProgress().percent).toBe(38.5);
    expect(getMediaProgress().recent).toEqual(["扫描媒体对象", "旧媒体"]);
  });

  it("updates threat progress state and recent labels", () => {
    const { options, getThreatProgress } = createOptions("__progress__:threat:3:6:扫描目标流");

    expect(updateProgressFromStatusState(options)).toBe(true);
    expect(getThreatProgress()).toMatchObject({
      active: true,
      current: 3,
      total: 6,
      label: "扫描目标流",
      phase: "streams",
      phaseLabel: "分析流",
      percent: 50,
      recent: ["扫描目标流", "旧威胁"],
    });
  });

  it("updates capture totals and processed refs", () => {
    const { options } = createOptions("__progress__:loading:8:100");

    expect(updateProgressFromStatusState(options)).toBe(true);
    expect(options.setPreloadTotal).toHaveBeenCalledWith(100);
    expect(options.setTotalPackets).toHaveBeenCalledWith(100);
    expect(options.preloadTotalRef.current).toBe(100);
    expect(options.setPreloadProcessed).toHaveBeenCalledWith(8);
    expect(options.preloadProcessedRef.current).toBe(8);
  });

  it("resets processed count during counting phase", () => {
    const { options } = createOptions("__progress__:counting:42:100");

    expect(updateProgressFromStatusState(options)).toBe(true);
    expect(options.setPreloadProcessed).toHaveBeenCalledWith(0);
    expect(options.preloadProcessedRef.current).toBe(0);
  });

  it("clamps negative processed values", () => {
    const { options } = createOptions("__progress__:loading:-3:0");

    expect(updateProgressFromStatusState(options)).toBe(true);
    expect(options.setPreloadProcessed).toHaveBeenCalledWith(0);
    expect(options.preloadProcessedRef.current).toBe(0);
  });
});
