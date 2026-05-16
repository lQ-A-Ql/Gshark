import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useCapturePreloadState } from "./useCapturePreloadState";

describe("useCapturePreloadState", () => {
  it("initializes all slice values to their defaults", () => {
    const { result } = renderHook(() => useCapturePreloadState());

    expect(result.current.isPreloadingCapture).toBe(false);
    expect(result.current.preloadProcessed).toBe(0);
    expect(result.current.preloadTotal).toBe(0);
    expect(result.current.capturePreloadDiagnostics).toBeNull();
    expect(result.current.preloadProcessedRef.current).toBe(0);
    expect(result.current.preloadTotalRef.current).toBe(0);
  });

  it("updates state via setters and keeps refs in sync after re-render", () => {
    const { result, rerender } = renderHook(() => useCapturePreloadState());

    act(() => {
      result.current.setIsPreloadingCapture(true);
      result.current.setPreloadProcessed(42);
      result.current.setPreloadTotal(100);
    });
    rerender();

    expect(result.current.isPreloadingCapture).toBe(true);
    expect(result.current.preloadProcessed).toBe(42);
    expect(result.current.preloadTotal).toBe(100);
    expect(result.current.preloadProcessedRef.current).toBe(42);
    expect(result.current.preloadTotalRef.current).toBe(100);
  });

  it("supports functional updates for the counter setters", () => {
    const { result, rerender } = renderHook(() => useCapturePreloadState());

    act(() => {
      result.current.setPreloadProcessed(10);
      result.current.setPreloadTotal(20);
    });
    rerender();

    act(() => {
      result.current.setPreloadProcessed((prev) => prev + 5);
      result.current.setPreloadTotal((prev) => prev * 2);
    });
    rerender();

    expect(result.current.preloadProcessed).toBe(15);
    expect(result.current.preloadTotal).toBe(40);
    expect(result.current.preloadProcessedRef.current).toBe(15);
    expect(result.current.preloadTotalRef.current).toBe(40);
  });
});
