import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PRELOAD_BUDGET } from "./preloadBudget";
import { useRoutePreloadIntent } from "./useRoutePreloadIntent";

const preloadRouteModuleMock = vi.fn();

vi.mock("./routePreload", () => ({
  preloadRouteModule: (...args: unknown[]) => preloadRouteModuleMock(...args),
}));

describe("useRoutePreloadIntent", () => {
  afterEach(() => {
    vi.useRealTimers();
    preloadRouteModuleMock.mockReset();
  });

  it("does not preload when hover leaves before delay", () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useRoutePreloadIntent());

    act(() => result.current.scheduleRoutePreloadIntent("/traffic-graph"));
    act(() => {
      vi.advanceTimersByTime(PRELOAD_BUDGET.hoverIntentDelayMs - 1);
      result.current.cancelRoutePreloadIntent("/traffic-graph");
      vi.advanceTimersByTime(10);
    });

    expect(preloadRouteModuleMock).not.toHaveBeenCalled();
  });

  it("preloads after hover delay", () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useRoutePreloadIntent());

    act(() => result.current.scheduleRoutePreloadIntent("/traffic-graph"));
    act(() => vi.advanceTimersByTime(PRELOAD_BUDGET.hoverIntentDelayMs));

    expect(preloadRouteModuleMock).toHaveBeenCalledWith("/traffic-graph", "hover");
  });

  it("preloads immediately on focus", () => {
    const { result } = renderHook(() => useRoutePreloadIntent());

    act(() => result.current.preloadRouteOnFocus("/traffic-graph"));

    expect(preloadRouteModuleMock).toHaveBeenCalledWith("/traffic-graph", "focus");
  });
});
