import { describe, expect, it } from "vitest";
import { buildTrafficTimelineEvents } from "./trafficTimelineEvents";

describe("buildTrafficTimelineEvents", () => {
  it("returns top peak events with highest point marked high severity", () => {
    const events = buildTrafficTimelineEvents([
      { label: "12:00:00", count: 10 },
      { label: "12:00:01", count: 42 },
      { label: "12:00:02", count: 28 },
      { label: "12:00:03", count: 17 },
      { label: "12:00:04", count: 14 },
      { label: "12:00:05", count: 9 },
    ]);

    const peakEvents = events.filter((event) => event.kind === "peak");
    expect(peakEvents).toHaveLength(5);
    expect(peakEvents.find((event) => event.label === "12:00:01")?.severity).toBe("high");
  });

  it("detects burst events using the previous up-to-five average and count threshold", () => {
    const events = buildTrafficTimelineEvents([
      { label: "12:00:00", count: 2 },
      { label: "12:00:01", count: 2 },
      { label: "12:00:02", count: 3 },
      { label: "12:00:03", count: 4 },
      { label: "12:00:04", count: 3 },
      { label: "12:00:05", count: 18 },
    ]);

    expect(events.some((event) => event.kind === "burst" && event.label === "12:00:05")).toBe(true);
  });

  it("returns no events for empty or malformed input", () => {
    expect(buildTrafficTimelineEvents([])).toEqual([]);
    expect(buildTrafficTimelineEvents([{ label: "", count: 10 }, { label: "12:00:00", count: Number.NaN }])).toEqual([]);
  });
});
