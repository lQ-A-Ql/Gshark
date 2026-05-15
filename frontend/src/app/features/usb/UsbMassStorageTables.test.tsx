import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MassStorageFilters } from "./UsbMassStorageTables";

describe("MassStorageFilters", () => {
  it("keeps device and LUN filtering behavior through global selects", async () => {
    const onDeviceChange = vi.fn();
    const onLunChange = vi.fn();
    render(
      <MassStorageFilters
        devices={["Bus 001 Device 002"]}
        luns={["0", "1"]}
        activeDevice="all"
        activeLun="all"
        onDeviceChange={onDeviceChange}
        onLunChange={onLunChange}
      />,
    );

    fireEvent.pointerDown(screen.getByRole("combobox", { name: "设备" }), {
      button: 0,
      ctrlKey: false,
      pointerType: "mouse",
    });
    const deviceOption = await screen.findByRole("option", { name: "Bus 001 Device 002" });
    fireEvent.keyDown(deviceOption, { key: "Enter" });
    expect(onDeviceChange).toHaveBeenCalledWith("Bus 001 Device 002");

    fireEvent.pointerDown(screen.getByRole("combobox", { name: "LUN" }), {
      button: 0,
      ctrlKey: false,
      pointerType: "mouse",
    });
    const lunOption = await screen.findByRole("option", { name: "1" });
    fireEvent.keyDown(lunOption, { key: "Enter" });
    expect(onLunChange).toHaveBeenCalledWith("1");
  });
});
