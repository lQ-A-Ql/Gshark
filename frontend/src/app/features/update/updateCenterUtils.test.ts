import { describe, expect, it } from "vitest";

import { formatReleaseTime } from "./updateCenterUtils";

describe("formatReleaseTime", () => {
  it("falls back to a friendly empty value", () => {
    expect(formatReleaseTime("")).toBe("未知");
  });

  it("keeps invalid input readable for diagnostics", () => {
    expect(formatReleaseTime("not-a-date")).toBe("not-a-date");
  });
});
