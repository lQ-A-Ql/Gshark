import { describe, expect, it } from "vitest";
import { canSchedulePrefetch, pickAdjacentStreamTargets } from "./streamPrefetchPlan";

describe("streamPrefetchPlan", () => {
  it("picks adjacent neighbors around current stream id", () => {
    expect(pickAdjacentStreamTargets([11, 22, 33, 44], 22, 2)).toEqual([33, 11]);
    expect(pickAdjacentStreamTargets([11, 22, 33, 44], 11, 2)).toEqual([22]);
    expect(pickAdjacentStreamTargets([11, 22, 33, 44], 44, 2)).toEqual([33]);
  });

  it("returns empty list for invalid inputs", () => {
    expect(pickAdjacentStreamTargets([1, 2], -1, 2)).toEqual([]);
    expect(pickAdjacentStreamTargets([1, 2], 1, 0)).toEqual([]);
    expect(pickAdjacentStreamTargets([1, 2], 99, 2)).toEqual([]);
  });

  it("checks cache and in-flight limits before scheduling", () => {
    expect(canSchedulePrefetch({ hasCached: true, inFlight: false, inFlightSize: 0 })).toBe(false);
    expect(canSchedulePrefetch({ hasCached: false, inFlight: true, inFlightSize: 0 })).toBe(false);
    expect(canSchedulePrefetch({ hasCached: false, inFlight: false, inFlightSize: 2 })).toBe(false);
    expect(canSchedulePrefetch({ hasCached: false, inFlight: false, inFlightSize: 1 })).toBe(true);
    expect(canSchedulePrefetch({ hasCached: false, inFlight: false, inFlightSize: 3, maxInFlight: 4 })).toBe(true);
  });
});
