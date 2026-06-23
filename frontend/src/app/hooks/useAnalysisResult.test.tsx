import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useAnalysisResult } from "./useAnalysisResult";
import { createAnalysisResourceCache } from "../core/analysisResourceCache";

describe("useAnalysisResult", () => {
  it("fetches and caches data", async () => {
    const cache = createAnalysisResourceCache<string>();
    const fetch = vi.fn().mockResolvedValueOnce("payload");

    const { result } = renderHook(() =>
      useAnalysisResult({
        cache,
        cacheKey: "k",
        emptyValue: "empty",
        enabled: true,
        isPreloadingCapture: false,
        errorMessage: "fail",
        fetch,
      }),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toBe("payload");
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(expect.any(AbortSignal), false);
  });

  it("returns cached data without refetching", async () => {
    const cache = createAnalysisResourceCache<string>();
    cache.set("k", "cached");
    const fetch = vi.fn().mockResolvedValueOnce("payload");

    const { result } = renderHook(() =>
      useAnalysisResult({
        cache,
        cacheKey: "k",
        emptyValue: "empty",
        enabled: true,
        isPreloadingCapture: false,
        errorMessage: "fail",
        fetch,
      }),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.data).toBe("cached");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bypasses cache when force is true", async () => {
    const cache = createAnalysisResourceCache<string>();
    cache.set("k", "cached");
    const fetch = vi.fn().mockResolvedValueOnce("fresh");

    const { result } = renderHook(() =>
      useAnalysisResult({
        cache,
        cacheKey: "k",
        emptyValue: "empty",
        enabled: true,
        isPreloadingCapture: false,
        errorMessage: "fail",
        fetch,
      }),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    result.current.refresh(true);

    await waitFor(() => expect(result.current.data).toBe("fresh"));
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(expect.any(AbortSignal), true);
  });

  it("does not fetch when disabled", async () => {
    const cache = createAnalysisResourceCache<string>();
    const fetch = vi.fn().mockResolvedValueOnce("payload");

    const { result } = renderHook(() =>
      useAnalysisResult({
        cache,
        cacheKey: "k",
        emptyValue: "empty",
        enabled: false,
        isPreloadingCapture: false,
        errorMessage: "fail",
        fetch,
      }),
    );

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(result.current.loading).toBe(false);
    expect(result.current.data).toBe("empty");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("calls onSuccess with payload", async () => {
    const cache = createAnalysisResourceCache<string>();
    const fetch = vi.fn().mockResolvedValueOnce("payload");
    const onSuccess = vi.fn();

    renderHook(() =>
      useAnalysisResult({
        cache,
        cacheKey: "k",
        emptyValue: "empty",
        enabled: true,
        isPreloadingCapture: false,
        errorMessage: "fail",
        fetch,
        onSuccess,
      }),
    );

    await waitFor(() => expect(onSuccess).toHaveBeenCalledWith("payload"));
  });

  it("returns error on failure", async () => {
    const cache = createAnalysisResourceCache<string>();
    const fetch = vi.fn().mockRejectedValueOnce(new Error("boom"));

    const { result } = renderHook(() =>
      useAnalysisResult({
        cache,
        cacheKey: "k",
        emptyValue: "empty",
        enabled: true,
        isPreloadingCapture: false,
        errorMessage: "fallback",
        fetch,
      }),
    );

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toContain("boom");
    expect(result.current.data).toBe("empty");
  });
});
