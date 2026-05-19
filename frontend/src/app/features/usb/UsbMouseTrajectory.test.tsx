import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { USBMouseEvent } from "../../core/types";
import { MouseTrajectory } from "./UsbMouseTrajectory";

describe("MouseTrajectory", () => {
  it("keeps the canvas chart legend and hints", () => {
    render(<MouseTrajectory coordinateMode="recovered" events={[makeMouseEvent(1, ["Left"])]} />);

    expect(screen.getByRole("img", { name: "鼠标轨迹图" })).toBeInTheDocument();
    ["左键", "右键", "无按键", "其他/多键", "起点", "终点", "Y 轴已取反", "连续轨迹"].forEach((label) => {
      expect(screen.getByText(label)).toBeInTheDocument();
    });
  });

  it("keeps the empty state copy for filtered charts", () => {
    render(<MouseTrajectory emptyLabel="暂无右键轨迹数据" events={[makeMouseEvent(1, ["Left"])]} filterKind="right" />);

    expect(screen.getByText("暂无右键轨迹数据")).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: "鼠标轨迹图" })).not.toBeInTheDocument();
  });
});

function makeMouseEvent(packetId: number, buttons: string[]): USBMouseEvent {
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
    positionX: packetId,
    positionY: packetId,
    summary: `event ${packetId}`,
  };
}
