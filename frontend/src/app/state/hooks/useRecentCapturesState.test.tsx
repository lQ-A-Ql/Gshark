import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { RecentCapture } from "../../core/types";
import { RECENT_CAPTURES_STORAGE_KEY } from "../recentCaptures";
import { useRecentCapturesState } from "./useRecentCapturesState";

function recent(path: string): RecentCapture {
  return {
    path,
    name: path.split("/").pop() ?? path,
    sizeBytes: path.length,
    lastOpenedAt: "2026-05-11T05:00:00.000Z",
  };
}

describe("useRecentCapturesState", () => {
  it("loads persisted captures and persists remembered entries", () => {
    const first = recent("/captures/first.pcapng");
    let stored = JSON.stringify([first]);
    vi.spyOn(window.localStorage, "getItem").mockImplementation((key) =>
      key === RECENT_CAPTURES_STORAGE_KEY ? stored : null,
    );
    vi.spyOn(window.localStorage, "setItem").mockImplementation((key, value) => {
      if (key === RECENT_CAPTURES_STORAGE_KEY) stored = value;
    });

    const { result } = renderHook(() => useRecentCapturesState());
    const second = recent("/captures/second.pcapng");

    expect(result.current.recentCaptures).toEqual([first]);

    act(() => {
      result.current.rememberRecentCapture(second);
    });

    expect(result.current.recentCaptures).toEqual([second, first]);
    expect(JSON.parse(stored)).toEqual([second, first]);
  });
});
