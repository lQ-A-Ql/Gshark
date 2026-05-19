import type { USBMouseEvent } from "../../core/types";
import { UsbHidEmptyState } from "./UsbHidEmptyState";
import { type MouseCoordinateMode, normalizeMousePointsForMode } from "./usbMouseGeometry";

export function MouseHeatmap({
  events,
  coordinateMode = "screen",
}: {
  events: USBMouseEvent[];
  coordinateMode?: MouseCoordinateMode;
}) {
  if (events.length === 0) {
    return <UsbHidEmptyState>暂无鼠标热区数据</UsbHidEmptyState>;
  }

  const width = 680;
  const height = 320;
  const points = normalizeMousePointsForMode(events, width, height, coordinateMode);
  const bucketSize = 18;
  const density = new Map<string, { x: number; y: number; count: number; clicks: number }>();

  points.forEach((point, index) => {
    const bucketX = Math.round(point.x / bucketSize) * bucketSize;
    const bucketY = Math.round(point.y / bucketSize) * bucketSize;
    const key = `${bucketX}:${bucketY}`;
    const current = density.get(key) ?? { x: bucketX, y: bucketY, count: 0, clicks: 0 };
    current.count += 1;
    if ((events[index]?.pressedButtons.length ?? 0) + (events[index]?.releasedButtons.length ?? 0) > 0) {
      current.clicks += 1;
    }
    density.set(key, current);
  });

  const hotspots = Array.from(density.values());
  const maxCount = Math.max(1, ...hotspots.map((item) => item.count));

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border border-border bg-[radial-gradient(circle_at_top,#bfdbfe,transparent_55%),linear-gradient(180deg,#f8fafc,#eef2ff)]">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-[320px] w-full">
          <rect width={width} height={height} fill="rgba(255,255,255,0.3)" />
          {hotspots.map((item) => {
            const radius = 8 + (item.count / maxCount) * 18;
            const opacity = 0.18 + (item.count / maxCount) * 0.55;
            return (
              <circle
                key={`${item.x}-${item.y}`}
                cx={item.x}
                cy={item.y}
                r={radius}
                fill={`rgba(37,99,235,${opacity})`}
              />
            );
          })}
          {hotspots
            .filter((item) => item.clicks > 0)
            .map((item) => (
              <circle
                key={`click-${item.x}-${item.y}`}
                cx={item.x}
                cy={item.y}
                r={6 + Math.min(item.clicks, 4) * 2}
                fill="rgba(220,38,38,0.55)"
                stroke="rgba(185,28,28,0.9)"
                strokeWidth="1.5"
              />
            ))}
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-blue-600" /> 停留密度
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-600" /> 点击热点
        </span>
        <span>{coordinateMode === "recovered" ? "Y 轴已取反" : "屏幕坐标"}</span>
      </div>
    </div>
  );
}
