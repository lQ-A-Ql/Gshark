import type { USBMouseEvent } from "../../core/types";
import { type MouseTrackKind } from "./usbHidRules";
import {
  buildMouseTrajectoryGeometry,
  type MouseCoordinateMode,
  type MouseScaleMode,
} from "./usbMouseGeometry";
import { MOUSE_TRAJECTORY_HEIGHT, MOUSE_TRAJECTORY_WIDTH, MouseTrajectoryView } from "./UsbMouseTrajectoryView";
export { MOUSE_TRAJECTORY_HEIGHT, MOUSE_TRAJECTORY_WIDTH, MouseTrajectoryView } from "./UsbMouseTrajectoryView";

export function MouseTrajectory({
  events,
  filterKind,
  coordinateMode = "screen",
  renderMode = "line",
  scaleMode = "fit",
  emptyLabel = "暂无鼠标轨迹数据",
}: {
  events: USBMouseEvent[];
  filterKind?: MouseTrackKind;
  coordinateMode?: MouseCoordinateMode;
  renderMode?: "line" | "points";
  scaleMode?: MouseScaleMode;
  emptyLabel?: string;
}) {
  const geometry = buildMouseTrajectoryGeometry(
    events,
    MOUSE_TRAJECTORY_WIDTH,
    MOUSE_TRAJECTORY_HEIGHT,
    coordinateMode,
    scaleMode,
  );

  return (
    <MouseTrajectoryView
      coordinateMode={coordinateMode}
      emptyLabel={emptyLabel}
      events={events}
      filterKind={filterKind}
      geometry={geometry}
      renderMode={renderMode}
      scaleMode={scaleMode}
    />
  );
}
