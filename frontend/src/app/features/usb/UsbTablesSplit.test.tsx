import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { USBKeyboardEvent, USBMassStorageOperation, USBMouseEvent } from "../../core/types";
import { KeyboardEventTable, MassStorageFilters, MassStorageOperationTable, MouseEventTable } from "./UsbTables";

const keyboardEvent: USBKeyboardEvent = {
  packetId: 1,
  time: "1.000000",
  device: "Keyboard A",
  endpoint: "EP 0x81",
  modifiers: ["Left Shift"],
  keys: ["A"],
  pressedModifiers: ["Left Shift"],
  releasedModifiers: [],
  pressedKeys: ["A"],
  releasedKeys: [],
  text: "A",
  summary: "press Left Shift + A",
};

const mouseEvent: USBMouseEvent = {
  packetId: 2,
  time: "1.100000",
  device: "Mouse A",
  endpoint: "EP 0x82",
  buttons: ["Left"],
  pressedButtons: ["Left"],
  releasedButtons: [],
  xDelta: 8,
  yDelta: 2,
  wheelVertical: 0,
  wheelHorizontal: 0,
  positionX: 8,
  positionY: 2,
  summary: "press Left / move=(+8,+2)",
};

const storageOperation: USBMassStorageOperation = {
  packetId: 20,
  time: "2.000000",
  device: "Disk A",
  endpoint: "EP 0x02 (OUT)",
  lun: "LUN 0",
  command: "WRITE(10)",
  operation: "write",
  transferLength: 512,
  direction: "OUT",
  status: "ok",
  requestFrame: 20,
  responseFrame: 21,
  latencyMs: 1.5,
  dataResidue: 4,
  summary: "WRITE(10)",
};

describe("Usb split tables", () => {
  it("renders HID keyboard and mouse rows through the compatibility barrel", () => {
    render(
      <>
        <KeyboardEventTable rows={[keyboardEvent]} />
        <MouseEventTable rows={[mouseEvent]} />
      </>,
    );

    expect(screen.getByText("Keyboard A")).toBeInTheDocument();
    expect(screen.getByText("press Left Shift + A")).toBeInTheDocument();
    expect(screen.getByText("Mouse A")).toBeInTheDocument();
    expect(screen.getByText("press Left / move=(+8,+2)")).toBeInTheDocument();
  });

  it("renders mass-storage filters and operation details", () => {
    const onDeviceChange = vi.fn();
    const onLunChange = vi.fn();

    render(
      <>
        <MassStorageFilters
          devices={["Disk A"]}
          luns={["LUN 0"]}
          activeDevice="all"
          activeLun="all"
          onDeviceChange={onDeviceChange}
          onLunChange={onLunChange}
        />
        <MassStorageOperationTable rows={[storageOperation]} />
      </>,
    );

    fireEvent.change(screen.getByLabelText("设备"), { target: { value: "Disk A" } });
    fireEvent.change(screen.getByLabelText("LUN"), { target: { value: "LUN 0" } });

    expect(onDeviceChange).toHaveBeenCalledWith("Disk A");
    expect(onLunChange).toHaveBeenCalledWith("LUN 0");
    expect(screen.getAllByText("WRITE(10)").length).toBeGreaterThan(0);
    expect(screen.getByText("residue=4")).toBeInTheDocument();
  });
});
