import { Route } from "lucide-react";
import type { USBMouseEvent } from "../../core/types";
import { UsbHidEmptyState } from "./UsbHidEmptyState";
import { normalizeMousePoints } from "./usbHidRules";

export function MouseTrajectory({ events }: { events: USBMouseEvent[] }) {
  if (events.length === 0) {
    return <UsbHidEmptyState>暂无鼠标轨迹数据</UsbHidEmptyState>;
  }

  const width = 680;
  const height = 320;
  const points = normalizeMousePoints(events, width, height);
  const polyline = points.map((point) => `${point.x},${point.y}`).join(" ");
  const start = polyline.split(" ")[0];
  const end = polyline.split(" ").at(-1);

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border border-border bg-[radial-gradient(circle_at_top,#dbeafe,transparent_60%),linear-gradient(180deg,#f8fafc,#eef2ff)]">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-[320px] w-full">
          <defs>
            <pattern id="mouse-grid" width="24" height="24" patternUnits="userSpaceOnUse">
              <path d="M 24 0 L 0 0 0 24" fill="none" stroke="rgba(148,163,184,0.18)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect width={width} height={height} fill="url(#mouse-grid)" />
          <polyline
            fill="none"
            stroke="#2563eb"
            strokeWidth="2.5"
            strokeLinejoin="round"
            strokeLinecap="round"
            points={polyline}
          />
          {start && <circle cx={start.split(",")[0]} cy={start.split(",")[1]} r="5" fill="#16a34a" />}
          {end && <circle cx={end.split(",")[0]} cy={end.split(",")[1]} r="5" fill="#dc2626" />}
        </svg>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-600" /> 起点
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-600" /> 终点
        </span>
        <span className="inline-flex items-center gap-1">
          <Route className="h-3.5 w-3.5" /> 轨迹基于相对位移累计
        </span>
      </div>
    </div>
  );
}
