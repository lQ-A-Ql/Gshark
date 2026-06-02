import { describe, expect, it } from "vitest";
import { asDBCProfile, asDBCProfiles } from "./dbcMapper";

describe("dbcMapper", () => {
  it("maps a single DBC profile from wire payload", () => {
    const result = asDBCProfile({
      path: "/data/vehicle.dbc",
      name: "OBD-II Standard",
      message_count: 42,
      signal_count: 128,
    });
    expect(result).toEqual({
      path: "/data/vehicle.dbc",
      name: "OBD-II Standard",
      messageCount: 42,
      signalCount: 128,
    });
  });

  it("defaults missing fields to empty/zero", () => {
    const result = asDBCProfile({});
    expect(result.path).toBe("");
    expect(result.name).toBe("");
    expect(result.messageCount).toBe(0);
    expect(result.signalCount).toBe(0);
  });

  it("handles null/undefined input gracefully", () => {
    const result = asDBCProfile(null);
    expect(result.path).toBe("");
    expect(result.name).toBe("");
  });

  it("maps an array of DBC profiles", () => {
    const result = asDBCProfiles([
      { path: "/a.dbc", name: "A", message_count: 10, signal_count: 20 },
      { path: "/b.dbc", name: "B", message_count: 5, signal_count: 8 },
    ]);
    expect(result).toHaveLength(2);
    expect(result[0].name).toBe("A");
    expect(result[1].signalCount).toBe(8);
  });

  it("returns empty array for non-array input", () => {
    expect(asDBCProfiles(null)).toEqual([]);
    expect(asDBCProfiles(undefined)).toEqual([]);
    expect(asDBCProfiles("not-array")).toEqual([]);
  });
});
