import { describe, expect, it } from "vitest";
import { asDBCProfiles, asPluginItem, asPluginItems } from "./pluginMapper";

describe("pluginMapper", () => {
  it("maps DBC profiles", () => {
    expect(asDBCProfiles([{ path: "car.dbc", name: "car", message_count: 3, signal_count: 12 }])).toEqual([
      { path: "car.dbc", name: "car", messageCount: 3, signalCount: 12 },
    ]);
    expect(asDBCProfiles(null)).toEqual([]);
  });

  it("maps plugin items", () => {
    expect(
      asPluginItem({
        id: "echo",
        name: "Echo",
        version: "1.0.0",
        tag: "misc",
        author: "qa",
        enabled: true,
        capabilities: ["run", 7],
      }),
    ).toMatchObject({
      id: "echo",
      name: "Echo",
      enabled: true,
      entry: "",
      runtime: "",
      capabilities: ["run", "7"],
    });
    expect(asPluginItems([{ id: "a" }, { id: "b" }])).toHaveLength(2);
  });
});
