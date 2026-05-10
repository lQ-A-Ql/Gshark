import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useStreamSwitchMetrics } from "./useStreamSwitchMetrics";

describe("useStreamSwitchMetrics", () => {
  it("records stream switch metrics while exposing reset refs for provider workflows", () => {
    const { result } = renderHook(() => useStreamSwitchMetrics());

    act(() => {
      result.current.recordStreamSwitchMetric("HTTP", 20, true);
    });

    expect(result.current.streamSwitchMetrics.overall).toMatchObject({ count: 1, lastMs: 20, cacheHitRate: 100 });
    expect(result.current.streamSwitchMetrics.byProtocol.HTTP).toMatchObject({
      count: 1,
      lastMs: 20,
      cacheHitRate: 100,
    });
    expect(result.current.streamSwitchDurationsRef.current.HTTP).toEqual([20]);
    expect(result.current.streamSwitchHitsRef.current.HTTP).toBe(1);
  });
});
