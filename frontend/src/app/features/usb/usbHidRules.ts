import type { USBKeyboardEvent, USBMouseEvent } from "../../core/types";

export function keyboardReplayToken(event: USBKeyboardEvent) {
  if (event.text) {
    return event.text;
  }
  if (event.pressedKeys.length > 0 || event.releasedKeys.length > 0) {
    return `[${event.summary}] `;
  }
  return "";
}

export function mouseActionBadge(row: USBMouseEvent) {
  if (row.pressedButtons.length > 0) return `press ${row.pressedButtons.join(", ")}`;
  if (row.releasedButtons.length > 0) return `release ${row.releasedButtons.join(", ")}`;
  if (row.wheelVertical !== 0 || row.wheelHorizontal !== 0) return "wheel";
  if (row.xDelta !== 0 || row.yDelta !== 0) return "move";
  return "event";
}

export function normalizeMousePoints(events: USBMouseEvent[], width: number, height: number) {
  const points = events.map((event) => ({ x: event.positionX, y: event.positionY }));
  const xs = points.map((point) => point.x);
  const ys = points.map((point) => point.y);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);
  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);

  return points.map((point) => ({
    x: ((point.x - minX) / spanX) * (width - 40) + 20,
    y: height - (((point.y - minY) / spanY) * (height - 40) + 20),
  }));
}
