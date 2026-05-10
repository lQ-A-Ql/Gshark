import { describe, expect, it, vi } from "vitest";
import { stopCaptureWorkflow, type StopCaptureWorkflowOptions } from "./captureStopWorkflow";

function createOptions(overrides: Partial<StopCaptureWorkflowOptions> = {}): StopCaptureWorkflowOptions {
  return {
    backendConnected: true,
    captureSeqRef: { current: 1 },
    filterSeqRef: { current: 2 },
    threatAnalysisSeqRef: { current: 3 },
    parseFinishedRef: { current: false },
    parseErrorRef: { current: "old" },
    preloadingRef: { current: true },
    setIsPreloadingCapture: vi.fn(),
    setIsFilterLoading: vi.fn(),
    cancelAllFrontendCaptureTasks: vi.fn(),
    wakeCaptureWaiters: vi.fn(),
    clearCaptureUiState: vi.fn(),
    setBackendStatus: vi.fn(),
    cancelMediaBatchTranscription: vi.fn(async () => undefined),
    closeCapture: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe("captureStopWorkflow", () => {
  it("clears frontend capture state and closes backend capture", async () => {
    const options = createOptions();

    await stopCaptureWorkflow(options);

    expect(options.captureSeqRef.current).toBe(2);
    expect(options.filterSeqRef.current).toBe(3);
    expect(options.threatAnalysisSeqRef.current).toBe(4);
    expect(options.parseFinishedRef.current).toBe(true);
    expect(options.parseErrorRef.current).toBe("");
    expect(options.preloadingRef.current).toBe(false);
    expect(options.setIsFilterLoading).toHaveBeenCalledWith(false);
    expect(options.cancelAllFrontendCaptureTasks).toHaveBeenCalledTimes(1);
    expect(options.wakeCaptureWaiters).toHaveBeenCalledTimes(1);
    expect(options.clearCaptureUiState).toHaveBeenCalledTimes(1);
    expect(options.cancelMediaBatchTranscription).toHaveBeenCalledTimes(1);
    expect(options.closeCapture).toHaveBeenCalledTimes(1);
    expect(options.setBackendStatus).toHaveBeenLastCalledWith("当前抓包已关闭，临时数据库已清理");
  });

  it("skips backend close when disconnected", async () => {
    const options = createOptions({ backendConnected: false });

    await stopCaptureWorkflow(options);

    expect(options.cancelMediaBatchTranscription).not.toHaveBeenCalled();
    expect(options.closeCapture).not.toHaveBeenCalled();
    expect(options.setBackendStatus).toHaveBeenCalledWith("当前抓包已从界面移除；后端未连接");
  });

  it("suppresses media cancellation failure but reports close failure", async () => {
    const options = createOptions({
      cancelMediaBatchTranscription: vi.fn(async () => {
        throw new Error("batch missing");
      }),
      closeCapture: vi.fn(async () => {
        throw new Error("close failed");
      }),
    });

    await stopCaptureWorkflow(options);

    expect(options.setBackendStatus).toHaveBeenLastCalledWith("当前抓包已从界面移除；后端清理返回: close failed");
  });
});
