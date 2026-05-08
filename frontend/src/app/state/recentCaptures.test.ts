import { describe, expect, it } from "vitest";
import { MAX_RECENT_CAPTURES, updateRecentCaptures } from "./recentCaptures";
import type { RecentCapture } from "../core/types";

function recent(path: string): RecentCapture {
  return {
    path,
    name: path.split("/").pop() ?? path,
    sizeBytes: path.length,
    lastOpenedAt: `2026-05-08T15:20:${path.length.toString().padStart(2, "0")}.000Z`,
  };
}

describe("recentCaptures helpers", () => {
  it("prepends a new capture", () => {
    const first = recent("/captures/first.pcapng");
    const second = recent("/captures/second.pcapng");

    expect(updateRecentCaptures([first], second)).toEqual([second, first]);
  });

  it("moves an existing capture to the front without duplicates", () => {
    const first = recent("/captures/first.pcapng");
    const second = recent("/captures/second.pcapng");
    const reopened = { ...first, lastOpenedAt: "2026-05-08T15:30:00.000Z" };

    expect(updateRecentCaptures([first, second], reopened)).toEqual([reopened, second]);
  });

  it("limits the recent capture list", () => {
    const existing = Array.from({ length: MAX_RECENT_CAPTURES }, (_, index) => recent(`/captures/${index}.pcapng`));
    const next = recent("/captures/new.pcapng");

    const updated = updateRecentCaptures(existing, next);

    expect(updated).toHaveLength(MAX_RECENT_CAPTURES);
    expect(updated[0]).toBe(next);
    expect(updated).not.toContain(existing[MAX_RECENT_CAPTURES - 1]);
  });
});
