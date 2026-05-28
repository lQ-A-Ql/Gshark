import { renderHook, waitFor, act } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { usePluginManager } from "./usePluginManager";

function createMockClient() {
  return {
    listPlugins: vi.fn().mockResolvedValue([
      { id: "p1", name: "Test Plugin", version: "1.0", tag: "", author: "test", enabled: true, entry: "plugin.js", runtime: "js", capabilities: ["packet.read"] },
    ]),
    getPluginSource: vi.fn().mockResolvedValue({ id: "p1", configPath: "", configContent: "{}", logicPath: "", logicContent: "", entry: "plugin.js" }),
    savePluginSource: vi.fn().mockResolvedValue({ id: "p1", configPath: "", configContent: "{}", logicPath: "", logicContent: "", entry: "plugin.js" }),
    addPlugin: vi.fn().mockResolvedValue({ id: "p2", name: "New", version: "1.0", tag: "", author: "", enabled: true, entry: "new.js", runtime: "js", capabilities: [] }),
    deletePlugin: vi.fn().mockResolvedValue(undefined),
    togglePlugin: vi.fn().mockResolvedValue({ id: "p1", name: "Test Plugin", version: "1.0", tag: "", author: "test", enabled: false, entry: "plugin.js", runtime: "js", capabilities: ["packet.read"] }),
    setPluginsEnabled: vi.fn().mockResolvedValue([]),
  };
}

describe("usePluginManager", () => {
  it("loads plugins on mount", async () => {
    const client = createMockClient();
    const { result } = renderHook(() => usePluginManager({ pluginClient: client as never }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.plugins).toHaveLength(1);
    expect(result.current.plugins[0].name).toBe("Test Plugin");
  });

  it("calls deletePlugin and refreshes", async () => {
    const client = createMockClient();
    const { result } = renderHook(() => usePluginManager({ pluginClient: client as never }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(() => result.current.deletePlugin("p1"));
    expect(client.deletePlugin).toHaveBeenCalledWith("p1");
    expect(client.listPlugins).toHaveBeenCalledTimes(2);
  });

  it("calls togglePlugin and refreshes", async () => {
    const client = createMockClient();
    const { result } = renderHook(() => usePluginManager({ pluginClient: client as never }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(() => result.current.togglePlugin("p1"));
    expect(client.togglePlugin).toHaveBeenCalledWith("p1");
  });

  it("calls addPlugin and refreshes", async () => {
    const client = createMockClient();
    const { result } = renderHook(() => usePluginManager({ pluginClient: client as never }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(() => result.current.addPlugin({ name: "New", entry: "new.js" }));
    expect(client.addPlugin).toHaveBeenCalled();
    expect(client.listPlugins).toHaveBeenCalledTimes(2);
  });

  it("sets error on listPlugins failure", async () => {
    const client = createMockClient();
    client.listPlugins.mockRejectedValueOnce(new Error("network error"));
    const { result } = renderHook(() => usePluginManager({ pluginClient: client as never }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe("network error");
  });

  it("loads plugin source", async () => {
    const client = createMockClient();
    const { result } = renderHook(() => usePluginManager({ pluginClient: client as never }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(() => result.current.openSource("p1"));
    expect(result.current.sourcePlugin).not.toBeNull();
    expect(result.current.sourcePlugin?.id).toBe("p1");
  });
});
