import { describe, expect, it } from "vitest";

import {
  getWorkspacePagerItems,
  getWorkspacePreloadPercent,
  shouldShowWorkspaceFilterLoadingBlankState,
} from "./workspaceViewRules";

describe("workspaceViewRules", () => {
  it("clamps preload progress to a display percent", () => {
    expect(getWorkspacePreloadPercent(0, 0)).toBe(0);
    expect(getWorkspacePreloadPercent(25, 100)).toBe(25);
    expect(getWorkspacePreloadPercent(150, 100)).toBe(100);
    expect(getWorkspacePreloadPercent(-1, 100)).toBe(0);
  });

  it("builds bounded pager items around the current page", () => {
    expect(getWorkspacePagerItems(1, 5)).toEqual([1, 2, 5]);
    expect(getWorkspacePagerItems(3, 5)).toEqual([1, 2, 3, 4, 5]);
    expect(getWorkspacePagerItems(5, 5)).toEqual([1, 4, 5]);
  });

  it("shows the filter blank state only for active empty filter loads", () => {
    expect(shouldShowWorkspaceFilterLoadingBlankState(0, true, false)).toBe(true);
    expect(shouldShowWorkspaceFilterLoadingBlankState(1, true, false)).toBe(false);
    expect(shouldShowWorkspaceFilterLoadingBlankState(0, true, true)).toBe(false);
  });
});
