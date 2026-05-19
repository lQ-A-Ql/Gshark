import type { USBMouseEvent } from "../../core/types";
import { type MouseTrackKind, mouseButtonTrackKind } from "./usbHidRules";

export type MouseCoordinateMode = "screen" | "recovered";
export type MouseScaleMode = "fit" | "aspect";
export type MousePoint = { x: number; y: number };
export type MouseTrajectoryGeometry = {
  indexes: Record<"all" | MouseTrackKind, number[]>;
  points: MousePoint[];
};

export function normalizeMousePoints(events: USBMouseEvent[], width: number, height: number) {
  return normalizeMousePointsForMode(events, width, height, "screen");
}

export function normalizeMousePointsForMode(
  events: USBMouseEvent[],
  width: number,
  height: number,
  coordinateMode: MouseCoordinateMode,
  scaleMode: MouseScaleMode = "fit",
) {
  if (events.length === 0) return [];

  const rawPoints: MousePoint[] = new Array(events.length);
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;

  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const x = event.positionX;
    const y = coordinateMode === "recovered" ? -event.positionY : event.positionY;
    rawPoints[index] = { x, y };
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
  }

  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);
  const drawableWidth = width - 40;
  const drawableHeight = height - 40;
  const scale = scaleMode === "aspect" ? Math.min(drawableWidth / spanX, drawableHeight / spanY) : 1;
  const offsetX = scaleMode === "aspect" ? (drawableWidth - spanX * scale) / 2 : 0;
  const offsetY = scaleMode === "aspect" ? (drawableHeight - spanY * scale) / 2 : 0;
  const normalizedPoints: MousePoint[] = new Array(events.length);

  for (let index = 0; index < rawPoints.length; index += 1) {
    const point = rawPoints[index];
    normalizedPoints[index] =
      scaleMode === "aspect"
        ? {
            x: (point.x - minX) * scale + 20 + offsetX,
            y: height - ((point.y - minY) * scale + 20 + offsetY),
          }
        : {
            x: ((point.x - minX) / spanX) * drawableWidth + 20,
            y: height - (((point.y - minY) / spanY) * drawableHeight + 20),
          };
  }

  return normalizedPoints;
}

export function buildMouseTrajectoryIndexes(events: USBMouseEvent[]) {
  const indexes: MouseTrajectoryGeometry["indexes"] = {
    all: [],
    left: [],
    right: [],
    none: [],
    other: [],
  };

  for (let index = 0; index < events.length; index += 1) {
    const kind = mouseButtonTrackKind(events[index]);
    indexes.all.push(index);
    indexes[kind].push(index);
  }

  return indexes;
}

export function buildMouseTrajectoryGeometry(
  events: USBMouseEvent[],
  width: number,
  height: number,
  coordinateMode: MouseCoordinateMode,
  scaleMode: MouseScaleMode = "fit",
): MouseTrajectoryGeometry {
  return {
    indexes: buildMouseTrajectoryIndexes(events),
    points: normalizeMousePointsForMode(events, width, height, coordinateMode, scaleMode),
  };
}
