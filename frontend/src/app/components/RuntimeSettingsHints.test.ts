import { describe, expect, it } from "vitest";

import { autoDetectedPathHint, joinHints } from "./RuntimeSettingsHints";

describe("RuntimeSettingsHints", () => {
  it("explains auto-detected paths only when no explicit config is set", () => {
    expect(autoDetectedPathHint(true, "", "C:\\Tools\\ffmpeg.exe", "FFmpeg")).toContain("通过 PATH/默认路径探测到");
    expect(autoDetectedPathHint(true, "C:\\Pinned\\ffmpeg.exe", "C:\\Tools\\ffmpeg.exe", "FFmpeg")).toBe("");
    expect(joinHints(" A ", "", undefined, "B")).toBe("A B");
  });
});
