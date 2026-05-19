import type { USBKeyboardEvent, USBMouseEvent } from "../../core/types";

export type MouseTrackKind = "left" | "right" | "none" | "other";

export function keyboardReplayToken(event: USBKeyboardEvent) {
  if (event.text) return event.text;
  return event.pressedKeys.length > 0 || event.releasedKeys.length > 0 ? `[${event.summary}] ` : "";
}

export function mouseActionBadge(row: USBMouseEvent) {
  if (row.pressedButtons.length > 0) return `press ${row.pressedButtons.join(", ")}`;
  if (row.releasedButtons.length > 0) return `release ${row.releasedButtons.join(", ")}`;
  if (row.wheelVertical !== 0 || row.wheelHorizontal !== 0) return "wheel";
  if (row.xDelta !== 0 || row.yDelta !== 0) return "move";
  return "event";
}

export function mouseButtonTrackKind(row: USBMouseEvent): MouseTrackKind {
  const left = row.buttons.includes("Left");
  const right = row.buttons.includes("Right");
  if (left && !right && row.buttons.length === 1) return "left";
  if (right && !left && row.buttons.length === 1) return "right";
  if (row.buttons.length === 0) return "none";
  return "other";
}
