import { describe, expect, it } from "vitest";
import { PRELOAD_TARGETS, validatePreloadTargets } from "./preloadTargets";

describe("preload targets", () => {
  it("keeps inventory valid", () => {
    expect(validatePreloadTargets()).toEqual([]);
  });

  it("keeps high-cost targets default off and behind a flag", () => {
    const highTargets = PRELOAD_TARGETS.filter((target) => target.cost === "high");

    expect(highTargets.length).toBeGreaterThan(0);
    for (const target of highTargets) {
      expect(target.enabledByDefault).toBe(false);
      expect(target.featureFlag).toBeTruthy();
      expect(target.timeoutMs).toBeGreaterThan(0);
    }
  });

  it("rejects malformed inventory entries", () => {
    const [sample] = PRELOAD_TARGETS;

    expect(
      validatePreloadTargets([
        {
          ...sample,
          targetId: "heavy:bad",
          kind: "heavy-analysis",
          cost: "high",
          enabledByDefault: true,
          timeoutMs: 0,
          featureFlag: undefined,
        },
      ]),
    ).toEqual([
      "heavy:bad: timeoutMs is required",
      "heavy:bad: HIGH must be default off",
      "heavy:bad: HIGH requires featureFlag",
      "heavy:bad: heavy must be abortable",
    ]);
  });
});
