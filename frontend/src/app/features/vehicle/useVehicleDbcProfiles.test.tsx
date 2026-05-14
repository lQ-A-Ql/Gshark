import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { useVehicleDbcProfiles } from "./useVehicleDbcProfiles";

function createClient() {
  return {
    listVehicleDBCProfiles: vi.fn().mockResolvedValue([{ path: "car.dbc", name: "car", messageCount: 2, signalCount: 8 }]),
    addVehicleDBC: vi.fn().mockResolvedValue([{ path: "truck.dbc", name: "truck", messageCount: 3, signalCount: 12 }]),
    removeVehicleDBC: vi.fn().mockResolvedValue([]),
    openDBCFile: vi.fn().mockResolvedValue({ filePath: "picked.dbc" }),
  };
}

describe("useVehicleDbcProfiles", () => {
  it("loads DBC profiles when backend is connected", async () => {
    const client = createClient();
    const { result } = renderHook(() => useVehicleDbcProfiles({ backendConnected: true, vehicleDBCClient: client }));

    await waitFor(() => expect(result.current.profiles).toHaveLength(1));

    expect(client.listVehicleDBCProfiles).toHaveBeenCalledTimes(1);
    expect(result.current.profiles[0]).toMatchObject({ path: "car.dbc", messageCount: 2 });
  });

  it("adds, removes, and clears input on successful DBC changes", async () => {
    const client = createClient();
    const { result } = renderHook(() => useVehicleDbcProfiles({ backendConnected: true, vehicleDBCClient: client }));
    await waitFor(() => expect(client.listVehicleDBCProfiles).toHaveBeenCalledTimes(1));

    act(() => {
      result.current.setPathInput("truck.dbc");
    });

    await act(async () => {
      await expect(result.current.addPath(result.current.pathInput)).resolves.toBe(true);
    });
    expect(client.addVehicleDBC).toHaveBeenCalledWith("truck.dbc");
    expect(result.current.pathInput).toBe("");
    expect(result.current.profiles).toEqual([{ path: "truck.dbc", name: "truck", messageCount: 3, signalCount: 12 }]);

    await act(async () => {
      await expect(result.current.removePath("truck.dbc")).resolves.toBe(true);
    });
    expect(client.removeVehicleDBC).toHaveBeenCalledWith("truck.dbc");
    expect(result.current.profiles).toEqual([]);
  });

  it("opens a DBC picker and ignores user-cancel errors", async () => {
    const client = createClient();
    client.openDBCFile.mockRejectedValueOnce(new Error("未选择 DBC 文件"));
    const { result } = renderHook(() => useVehicleDbcProfiles({ backendConnected: true, vehicleDBCClient: client }));
    await waitFor(() => expect(client.listVehicleDBCProfiles).toHaveBeenCalledTimes(1));

    await act(async () => {
      await expect(result.current.importFile()).resolves.toBe(false);
    });

    expect(result.current.error).toBe("");
  });
});
