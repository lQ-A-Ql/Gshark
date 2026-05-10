import { describe, expect, it, vi } from "vitest";
import { prepareCaptureReplacementState, type PrepareCaptureReplacementOptions } from "./captureReplacementPrepare";

function createOptions(overrides: Partial<PrepareCaptureReplacementOptions> = {}): PrepareCaptureReplacementOptions {
  return {
    backendConnected: true,
    parseFinishedRef: { current: false },
    parseErrorRef: { current: "old error" },
    preloadingRef: { current: true },
    preloadProcessedRef: { current: 42 },
    preloadTotalRef: { current: 100 },
    cancelAllFrontendCaptureTasks: vi.fn(),
    wakeCaptureWaiters: vi.fn(),
    setIsPreloadingCapture: vi.fn(),
    setIsFilterLoading: vi.fn(),
    setPreloadProcessed: vi.fn(),
    setPreloadTotal: vi.fn(),
    stopStreamingPackets: vi.fn(async () => undefined),
    prepareCaptureReplacement: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("captureReplacementPrepare", () => {
  it("cancels frontend tasks and resets parse/filter/preload state", async () => {
    const options = createOptions({ backendConnected: false });

    await prepareCaptureReplacementState(options);

    expect(options.cancelAllFrontendCaptureTasks).toHaveBeenCalledTimes(1);
    expect(options.wakeCaptureWaiters).toHaveBeenCalledTimes(1);
    expect(options.preloadingRef.current).toBe(false);
    expect(options.parseFinishedRef.current).toBe(true);
    expect(options.parseErrorRef.current).toBe("");
    expect(options.preloadProcessedRef.current).toBe(0);
    expect(options.preloadTotalRef.current).toBe(0);
    expect(options.setIsPreloadingCapture).toHaveBeenCalledWith(false);
    expect(options.setIsFilterLoading).toHaveBeenCalledWith(false);
    expect(options.setPreloadProcessed).toHaveBeenCalledWith(0);
    expect(options.setPreloadTotal).toHaveBeenCalledWith(0);
  });

  it("notifies backend when connected and suppresses cleanup failures", async () => {
    const options = createOptions({
      stopStreamingPackets: vi.fn(async () => {
        throw new Error("already stopped");
      }),
    });

    await prepareCaptureReplacementState(options);

    expect(options.stopStreamingPackets).toHaveBeenCalledTimes(1);
    expect(options.prepareCaptureReplacement).toHaveBeenCalledTimes(1);
  });

  it("skips backend cleanup when disconnected", async () => {
    const options = createOptions({ backendConnected: false });

    await prepareCaptureReplacementState(options);

    expect(options.stopStreamingPackets).not.toHaveBeenCalled();
    expect(options.prepareCaptureReplacement).not.toHaveBeenCalled();
  });
});
