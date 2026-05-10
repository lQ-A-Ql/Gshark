import { act, renderHook } from "@testing-library/react";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { useCaptureReplacementPrepare } from "./useCaptureReplacementPrepare";

describe("useCaptureReplacementPrepare", () => {
  it("wires replacement reset state and backend cleanup through refs", async () => {
    const cancelAllFrontendCaptureTasks = vi.fn();
    const wakeCaptureWaiters = vi.fn();
    const stopStreamingPackets = vi.fn(async () => undefined);
    const prepareCaptureReplacement = vi.fn(async () => undefined);

    const { result } = renderHook(() => {
      const parseFinishedRef = useRef(false);
      const parseErrorRef = useRef("stale error");
      const preloadingRef = useRef(true);
      const preloadProcessedRef = useRef(12);
      const preloadTotalRef = useRef(24);
      const [isPreloadingCapture, setIsPreloadingCapture] = useState(true);
      const [isFilterLoading, setIsFilterLoading] = useState(true);
      const [preloadProcessed, setPreloadProcessed] = useState(12);
      const [preloadTotal, setPreloadTotal] = useState(24);
      const prepareForCaptureReplacement = useCaptureReplacementPrepare({
        backendConnected: true,
        parseFinishedRef,
        parseErrorRef,
        preloadingRef,
        preloadProcessedRef,
        preloadTotalRef,
        cancelAllFrontendCaptureTasks,
        wakeCaptureWaiters,
        setIsPreloadingCapture,
        setIsFilterLoading,
        setPreloadProcessed,
        setPreloadTotal,
        stopStreamingPackets,
        prepareCaptureReplacement,
      });
      return {
        prepareForCaptureReplacement,
        parseFinishedRef,
        parseErrorRef,
        preloadingRef,
        preloadProcessedRef,
        preloadTotalRef,
        isPreloadingCapture,
        isFilterLoading,
        preloadProcessed,
        preloadTotal,
      };
    });

    await act(async () => result.current.prepareForCaptureReplacement());

    expect(cancelAllFrontendCaptureTasks).toHaveBeenCalledTimes(1);
    expect(wakeCaptureWaiters).toHaveBeenCalledTimes(1);
    expect(result.current.parseFinishedRef.current).toBe(true);
    expect(result.current.parseErrorRef.current).toBe("");
    expect(result.current.preloadingRef.current).toBe(false);
    expect(result.current.preloadProcessedRef.current).toBe(0);
    expect(result.current.preloadTotalRef.current).toBe(0);
    expect(result.current.isPreloadingCapture).toBe(false);
    expect(result.current.isFilterLoading).toBe(false);
    expect(result.current.preloadProcessed).toBe(0);
    expect(result.current.preloadTotal).toBe(0);
    expect(stopStreamingPackets).toHaveBeenCalledTimes(1);
    expect(prepareCaptureReplacement).toHaveBeenCalledTimes(1);
  });

  it("keeps latest backend connection state without changing callback identity", async () => {
    const stopStreamingPackets = vi.fn(async () => undefined);
    const prepareCaptureReplacement = vi.fn(async () => undefined);
    let backendConnected = false;

    const { rerender, result } = renderHook(() => {
      const parseFinishedRef = useRef(false);
      const parseErrorRef = useRef("");
      const preloadingRef = useRef(false);
      const preloadProcessedRef = useRef(0);
      const preloadTotalRef = useRef(0);
      const prepareForCaptureReplacement = useCaptureReplacementPrepare({
        backendConnected,
        parseFinishedRef,
        parseErrorRef,
        preloadingRef,
        preloadProcessedRef,
        preloadTotalRef,
        cancelAllFrontendCaptureTasks: vi.fn(),
        wakeCaptureWaiters: vi.fn(),
        setIsPreloadingCapture: vi.fn(),
        setIsFilterLoading: vi.fn(),
        setPreloadProcessed: vi.fn(),
        setPreloadTotal: vi.fn(),
        stopStreamingPackets,
        prepareCaptureReplacement,
      });
      return prepareForCaptureReplacement;
    });

    const firstCallback = result.current;
    backendConnected = true;
    rerender();

    expect(result.current).toBe(firstCallback);
    await act(async () => result.current());
    expect(stopStreamingPackets).toHaveBeenCalledTimes(1);
    expect(prepareCaptureReplacement).toHaveBeenCalledTimes(1);
  });
});
