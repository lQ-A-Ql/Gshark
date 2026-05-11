import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { useCaptureStopWorkflow } from "./useCaptureStopWorkflow";

describe("useCaptureStopWorkflow", () => {
  it("wires stop capture workflow through provider refs and setters", async () => {
    const cancelAllFrontendCaptureTasks = vi.fn();
    const wakeCaptureWaiters = vi.fn();
    const clearCaptureUiState = vi.fn();
    const cancelMediaBatchTranscription = vi.fn(async () => undefined);
    const closeCapture = vi.fn(async () => undefined);
    const setBackendStatus = vi.fn();

    const { result } = renderHook(() => {
      const captureSeqRef = useRef(1);
      const filterSeqRef = useRef(2);
      const threatAnalysisSeqRef = useRef(3);
      const parseFinishedRef = useRef(false);
      const parseErrorRef = useRef("stale parse");
      const preloadingRef = useRef(true);
      const [isPreloadingCapture, setIsPreloadingCapture] = useState(true);
      const [isFilterLoading, setIsFilterLoading] = useState(true);
      const stopCapture = useCaptureStopWorkflow({
        backendConnected: true,
        captureSeqRef,
        filterSeqRef,
        threatAnalysisSeqRef,
        parseFinishedRef,
        parseErrorRef,
        preloadingRef,
        setIsPreloadingCapture,
        setIsFilterLoading,
        cancelAllFrontendCaptureTasks,
        wakeCaptureWaiters,
        clearCaptureUiState,
        setBackendStatus,
        cancelMediaBatchTranscription,
        closeCapture,
      });
      return {
        stopCapture,
        captureSeqRef,
        filterSeqRef,
        threatAnalysisSeqRef,
        parseFinishedRef,
        parseErrorRef,
        preloadingRef,
        isPreloadingCapture,
        isFilterLoading,
      };
    });

    await act(async () => result.current.stopCapture());

    expect(result.current.captureSeqRef.current).toBe(2);
    expect(result.current.filterSeqRef.current).toBe(3);
    expect(result.current.threatAnalysisSeqRef.current).toBe(4);
    expect(result.current.parseFinishedRef.current).toBe(true);
    expect(result.current.parseErrorRef.current).toBe("");
    expect(result.current.preloadingRef.current).toBe(false);
    expect(result.current.isPreloadingCapture).toBe(false);
    expect(result.current.isFilterLoading).toBe(false);
    expect(cancelAllFrontendCaptureTasks).toHaveBeenCalledTimes(1);
    expect(wakeCaptureWaiters).toHaveBeenCalledTimes(1);
    expect(clearCaptureUiState).toHaveBeenCalledTimes(1);
    expect(cancelMediaBatchTranscription).toHaveBeenCalledTimes(1);
    expect(closeCapture).toHaveBeenCalledTimes(1);
    expect(setBackendStatus).toHaveBeenLastCalledWith("当前抓包已关闭，临时数据库已清理");
  });

  it("uses latest backend connection state while preserving callback identity", async () => {
    const cancelMediaBatchTranscription = vi.fn(async () => undefined);
    const closeCapture = vi.fn(async () => undefined);
    let backendConnected = false;

    const { rerender, result } = renderHook(() => {
      const stopCapture = useCaptureStopWorkflow({
        backendConnected,
        captureSeqRef: useRef(0),
        filterSeqRef: useRef(0),
        threatAnalysisSeqRef: useRef(0),
        parseFinishedRef: useRef(false),
        parseErrorRef: useRef(""),
        preloadingRef: useRef(false),
        setIsPreloadingCapture: vi.fn(),
        setIsFilterLoading: vi.fn(),
        cancelAllFrontendCaptureTasks: vi.fn(),
        wakeCaptureWaiters: vi.fn(),
        clearCaptureUiState: vi.fn(),
        setBackendStatus: vi.fn(),
        cancelMediaBatchTranscription,
        closeCapture,
      });
      return stopCapture;
    });

    const firstCallback = result.current;
    backendConnected = true;
    rerender();

    expect(result.current).toBe(firstCallback);
    await act(async () => result.current());
    expect(cancelMediaBatchTranscription).toHaveBeenCalledTimes(1);
    expect(closeCapture).toHaveBeenCalledTimes(1);
  });
});
