import type { USBMouseEvent } from "../../core/types";
import { UsbHidEmptyState } from "./UsbHidEmptyState";
import { type MouseTrackKind } from "./usbHidRules";
import type { MouseCoordinateMode, MouseScaleMode, MouseTrajectoryGeometry } from "./usbMouseGeometry";
import { MouseTrajectoryLegend } from "./UsbMouseTrajectoryLegend";
import { MouseTrajectorySvg } from "./UsbMouseTrajectorySvg";

export const MOUSE_TRAJECTORY_WIDTH = 680;
export const MOUSE_TRAJECTORY_HEIGHT = 320;

export function MouseTrajectoryView({
  events,
  geometry,
  filterKind,
  coordinateMode = "screen",
  renderMode = "line",
  scaleMode = "fit",
  emptyLabel = "暂无鼠标轨迹数据",
}: {
  events: USBMouseEvent[];
  geometry: MouseTrajectoryGeometry;
  filterKind?: MouseTrackKind;
  coordinateMode?: MouseCoordinateMode;
  renderMode?: "line" | "points";
  scaleMode?: MouseScaleMode;
  emptyLabel?: string;
}) {
  const indexes = geometry.indexes[filterKind ?? "all"];
  if (indexes.length === 0) return <UsbHidEmptyState>{emptyLabel}</UsbHidEmptyState>;

  return (
    <div className="space-y-3">
      <div className="overflow-hidden rounded-xl border border-border bg-[radial-gradient(circle_at_top,#dbeafe,transparent_60%),linear-gradient(180deg,#f8fafc,#eef2ff)]">
        <MouseTrajectorySvg
          events={events}
          filterKind={filterKind}
          height={MOUSE_TRAJECTORY_HEIGHT}
          indexes={indexes}
          points={geometry.points}
          renderMode={renderMode}
          width={MOUSE_TRAJECTORY_WIDTH}
        />
      </div>
      <MouseTrajectoryLegend coordinateMode={coordinateMode} renderMode={renderMode} scaleMode={scaleMode} />
    </div>
  );
}
