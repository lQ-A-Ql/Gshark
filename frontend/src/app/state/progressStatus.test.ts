import { describe, expect, it } from "vitest";
import { parseProgressStatus, pushRecentLabel } from "./progressStatus";

describe("progressStatus helpers", () => {
  it("ignores ordinary backend status messages", () => {
    expect(parseProgressStatus("后端已连接")).toEqual({ consumed: false });
  });

  it("parses media and threat progress labels with colons intact", () => {
    expect(parseProgressStatus("__progress__:media:2:10:extract:audio")).toEqual({
      consumed: true,
      kind: "media",
      current: 2,
      total: 10,
      label: "extract:audio",
    });
    expect(parseProgressStatus("__progress__:threat:3:8:yara scan")).toEqual({
      consumed: true,
      kind: "threat",
      current: 3,
      total: 8,
      label: "yara scan",
    });
  });

  it("parses capture progress and marks truncated messages as malformed", () => {
    expect(parseProgressStatus("__progress__:counting:0:42")).toEqual({
      consumed: true,
      kind: "capture",
      phase: "counting",
      processed: 0,
      total: 42,
    });
    expect(parseProgressStatus("__progress__:capture")).toEqual({ consumed: true, kind: "malformed" });
  });

  it("deduplicates recent labels and preserves empty labels", () => {
    expect(pushRecentLabel(["b", "a"], "a", 3)).toEqual(["a", "b"]);
    expect(pushRecentLabel(["a", "b"], "c", 2)).toEqual(["c", "a"]);
    const existing = ["a"];
    expect(pushRecentLabel(existing, "", 2)).toBe(existing);
  });
});
