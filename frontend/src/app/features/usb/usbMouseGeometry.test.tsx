import { describe, expect, it } from "vitest";
import type { USBMouseEvent } from "../../core/types";
import { buildMouseTrajectoryIndexes, normalizeMousePointsForMode } from "./usbMouseGeometry";

describe("usb mouse geometry", () => {
  it("builds trajectory indexes for all button states in one pass", () => {
    const events = [
      makeMouseEvent(1, []),
      makeMouseEvent(2, ["Left"]),
      makeMouseEvent(3, ["Right"]),
      makeMouseEvent(4, ["Left", "Right"]),
      makeMouseEvent(5, ["Middle"]),
    ];

    expect(buildMouseTrajectoryIndexes(events)).toEqual({
      all: [0, 1, 2, 3, 4],
      left: [1],
      right: [2],
      none: [0],
      other: [3, 4],
    });
  });

  it("returns empty indexes for empty mouse events", () => {
    expect(buildMouseTrajectoryIndexes([])).toEqual({
      all: [],
      left: [],
      right: [],
      none: [],
      other: [],
    });
  });

  it("normalizes 100k mouse events without spreading large arrays", () => {
    const events: USBMouseEvent[] = [];
    for (let index = 0; index < 100000; index += 1) {
      events.push(makeMouseEvent(index + 1, [], index % 2000, Math.trunc(index / 10) % 2000));
    }

    expect(() => normalizeMousePointsForMode(events, 680, 320, "recovered", "aspect")).not.toThrow();
    expect(normalizeMousePointsForMode(events, 680, 320, "recovered", "aspect")).toHaveLength(100000);
  });
});

function makeMouseEvent(packetId: number, buttons: string[], positionX = packetId, positionY = packetId): USBMouseEvent {
  return {
    packetId,
    time: `${packetId}.000000`,
    device: "Mouse A",
    endpoint: "EP 0x82",
    buttons,
    pressedButtons: [],
    releasedButtons: [],
    xDelta: 1,
    yDelta: 1,
    wheelVertical: 0,
    wheelHorizontal: 0,
    positionX,
    positionY,
    summary: `event ${packetId}`,
  };
}
