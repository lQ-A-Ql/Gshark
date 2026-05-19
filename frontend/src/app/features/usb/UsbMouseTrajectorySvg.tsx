import { useEffect, useRef } from "react";
import type { USBMouseEvent } from "../../core/types";
import type { MousePoint } from "./usbMouseGeometry";
import { type MouseTrackKind, mouseButtonTrackKind } from "./usbHidRules";

export const mouseTrackStyles: Record<MouseTrackKind, { label: string; stroke: string; dot: string }> = {
  left: { label: "左键", stroke: "#2563eb", dot: "bg-blue-600" },
  right: { label: "右键", stroke: "#e11d48", dot: "bg-rose-600" },
  none: { label: "无按键", stroke: "#64748b", dot: "bg-slate-500" },
  other: { label: "其他/多键", stroke: "#7c3aed", dot: "bg-violet-600" },
};

export function MouseTrajectoryCanvas({
  events,
  indexes,
  points,
  filterKind,
  renderMode = "line",
  height,
  width,
}: {
  events: USBMouseEvent[];
  indexes: number[];
  points: MousePoint[];
  filterKind?: MouseTrackKind;
  height: number;
  renderMode?: "line" | "points";
  width: number;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const context = canvas.getContext("2d");
    if (!context) return;

    const pixelRatio = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * pixelRatio);
    canvas.height = Math.round(height * pixelRatio);
    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    context.clearRect(0, 0, width, height);
    drawGrid(context, width, height);

    if (indexes.length > 0) {
      if (renderMode === "line") {
        drawLines(context, events, indexes, points, filterKind);
        drawPoints(context, events, indexes, points, filterKind, 2.2);
      } else {
        drawPoints(context, events, indexes, points, filterKind, 3.2);
      }
      drawEndpoint(context, points[indexes[0]], "#16a34a", 5);
      drawEndpoint(context, points[indexes[indexes.length - 1]], "#dc2626", 5);
    }
  }, [events, filterKind, height, indexes, points, renderMode, width]);

  return (
    <canvas
      ref={canvasRef}
      aria-label="鼠标轨迹图"
      className="h-[320px] w-full"
      role="img"
      style={{ aspectRatio: `${width} / ${height}` }}
    />
  );
}

export { MouseTrajectoryCanvas as MouseTrajectorySvg };

function drawGrid(context: CanvasRenderingContext2D, width: number, height: number) {
  context.save();
  context.strokeStyle = "rgba(148,163,184,0.18)";
  context.lineWidth = 1;
  context.beginPath();
  for (let x = 0; x <= width; x += 24) {
    context.moveTo(x, 0);
    context.lineTo(x, height);
  }
  for (let y = 0; y <= height; y += 24) {
    context.moveTo(0, y);
    context.lineTo(width, y);
  }
  context.stroke();
  context.restore();
}

function drawLines(
  context: CanvasRenderingContext2D,
  events: USBMouseEvent[],
  indexes: number[],
  points: MousePoint[],
  filterKind?: MouseTrackKind,
) {
  context.save();
  context.lineWidth = 2.5;
  context.lineCap = "round";
  context.lineJoin = "round";

  if (filterKind) {
    context.strokeStyle = mouseTrackStyles[filterKind].stroke;
    context.beginPath();
    for (let visibleIndex = 0; visibleIndex < indexes.length; visibleIndex += 1) {
      const point = points[indexes[visibleIndex]];
      if (visibleIndex === 0) context.moveTo(point.x, point.y);
      else context.lineTo(point.x, point.y);
    }
    context.stroke();
    context.restore();
    return;
  }

  for (let visibleIndex = 1; visibleIndex < indexes.length; visibleIndex += 1) {
    const previous = points[indexes[visibleIndex - 1]];
    const currentIndex = indexes[visibleIndex];
    const current = points[currentIndex];
    context.strokeStyle = mouseTrackStyles[mouseButtonTrackKind(events[currentIndex])].stroke;
    context.beginPath();
    context.moveTo(previous.x, previous.y);
    context.lineTo(current.x, current.y);
    context.stroke();
  }
  context.restore();
}

function drawPoints(
  context: CanvasRenderingContext2D,
  events: USBMouseEvent[],
  indexes: number[],
  points: MousePoint[],
  filterKind: MouseTrackKind | undefined,
  radius: number,
) {
  context.save();
  context.globalAlpha = 0.85;
  for (let visibleIndex = 0; visibleIndex < indexes.length; visibleIndex += 1) {
    const eventIndex = indexes[visibleIndex];
    const point = points[eventIndex];
    context.fillStyle = mouseTrackStyles[filterKind ?? mouseButtonTrackKind(events[eventIndex])].stroke;
    context.beginPath();
    context.arc(point.x, point.y, radius, 0, Math.PI * 2);
    context.fill();
  }
  context.restore();
}

function drawEndpoint(context: CanvasRenderingContext2D, point: MousePoint | undefined, color: string, radius: number) {
  if (!point) return;
  context.save();
  context.fillStyle = color;
  context.beginPath();
  context.arc(point.x, point.y, radius, 0, Math.PI * 2);
  context.fill();
  context.restore();
}
