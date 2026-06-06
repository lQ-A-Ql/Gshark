import { afterEach, describe, expect, it, vi } from "vitest";
import type { RouteModuleLoader } from "../routeModuleLoaders";
import { preloadRouteModule, resetRoutePreloadForTest, setRoutePreloadLoadersForTest } from "./routePreload";
import { setPreloadTelemetrySinkForTest } from "./preloadTelemetry";

const component = () => null;

describe("preloadRouteModule", () => {
  afterEach(() => {
    resetRoutePreloadForTest();
    setPreloadTelemetrySinkForTest(undefined);
  });

  it("dedupes same route imports", async () => {
    const loader = vi.fn<RouteModuleLoader>(() => Promise.resolve({ default: component }));
    setRoutePreloadLoadersForTest({ "/traffic-graph": loader });

    await Promise.all([
      preloadRouteModule("/traffic-graph"),
      preloadRouteModule("/traffic-graph"),
      preloadRouteModule("/traffic-graph"),
    ]);

    expect(loader).toHaveBeenCalledTimes(1);
  });

  it("clears failed import so retry can run", async () => {
    const loader = vi
      .fn<RouteModuleLoader>()
      .mockRejectedValueOnce(new Error("chunk failed"))
      .mockResolvedValueOnce({ default: component });
    setRoutePreloadLoadersForTest({ "/traffic-graph": loader });

    await preloadRouteModule("/traffic-graph");
    await preloadRouteModule("/traffic-graph");

    expect(loader).toHaveBeenCalledTimes(2);
  });

  it("safe-skips unknown routes", async () => {
    const events: string[] = [];
    setPreloadTelemetrySinkForTest((event) => events.push(`${event.event}:${event.reason ?? ""}`));
    setRoutePreloadLoadersForTest({});

    await expect(preloadRouteModule("/nope")).resolves.toBeUndefined();

    expect(events).toEqual(["preload.skipped:unknown-route"]);
  });
});
