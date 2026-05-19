import { Route } from "lucide-react";
import type { MouseCoordinateMode, MouseScaleMode } from "./usbMouseGeometry";
import { mouseTrackStyles } from "./UsbMouseTrajectorySvg";

export function MouseTrajectoryLegend({
  coordinateMode,
  renderMode,
  scaleMode,
}: {
  coordinateMode: MouseCoordinateMode;
  renderMode: "line" | "points";
  scaleMode: MouseScaleMode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
      {Object.entries(mouseTrackStyles).map(([kind, style]) => (
        <span key={kind} className="inline-flex items-center gap-1">
          <span className={`h-2.5 w-2.5 rounded-full ${style.dot}`} /> {style.label}
        </span>
      ))}
      <span className="inline-flex items-center gap-1">
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-600" /> 起点
      </span>
      <span className="inline-flex items-center gap-1">
        <span className="h-2.5 w-2.5 rounded-full bg-rose-600" /> 终点
      </span>
      <span className="inline-flex items-center gap-1">
        <Route className="h-3.5 w-3.5" /> 轨迹基于相对位移累计
      </span>
      <span>{coordinateMode === "recovered" ? "Y 轴已取反" : "屏幕坐标"}</span>
      <span>{renderMode === "points" ? "点阵轨迹" : "连续轨迹"}</span>
      <span>{scaleMode === "aspect" ? "等比例缩放" : "适配缩放"}</span>
    </div>
  );
}
