import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { MiscModuleManifest } from "../core/types";
import { useMiscToolsCatalog } from "./useMiscToolsCatalog";

const firstModule: MiscModuleManifest = {
  id: "payload-webshell-decoder",
  kind: "builtin",
  title: "Payload Decoder",
  summary: "Decode payloads",
  tags: ["WebShell"],
  apiPrefix: "/api/tools/misc/payload-webshell-decoder",
  requiresCapture: false,
};

const secondModule: MiscModuleManifest = {
  id: "custom-demo",
  kind: "custom",
  title: "Custom Demo",
  summary: "Custom module",
  tags: ["Custom"],
  apiPrefix: "/api/tools/misc/packages/custom-demo",
  requiresCapture: false,
};

function createClient(initialModules: MiscModuleManifest[] = [firstModule, secondModule]) {
  return {
    listMiscModules: vi.fn().mockResolvedValue(initialModules),
    importMiscModulePackage: vi.fn().mockResolvedValue(undefined),
  };
}

describe("useMiscToolsCatalog", () => {
  it("loads modules and mounts the first module by default", async () => {
    const miscModuleClient = createClient();

    const { result } = renderHook(() => useMiscToolsCatalog({ miscModuleClient }));

    await waitFor(() => expect(result.current.loading).toBe(false));

    expect(result.current.modules).toEqual([firstModule, secondModule]);
    expect(result.current.expandedModules).toEqual({ "payload-webshell-decoder": true, "custom-demo": false });
    expect(result.current.mountedModules).toEqual({ "payload-webshell-decoder": true });
  });

  it("imports a module, refreshes catalog, and returns to the Misc category", async () => {
    const file = new File(["zip"], "module.zip", { type: "application/zip" });
    const miscModuleClient = createClient([firstModule]);
    miscModuleClient.listMiscModules.mockResolvedValueOnce([firstModule]).mockResolvedValueOnce([secondModule]);

    const { result } = renderHook(() => useMiscToolsCatalog({ miscModuleClient }));
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      result.current.setActiveCategory("Payload");
    });

    await act(async () => {
      await expect(result.current.importModule(file)).resolves.toBeUndefined();
    });

    expect(miscModuleClient.importMiscModulePackage).toHaveBeenCalledWith(file);
    expect(result.current.modules).toEqual([secondModule]);
    expect(result.current.activeCategory).toBe("Misc");
  });

  it("records load and import errors as user-visible messages", async () => {
    const miscModuleClient = createClient();
    miscModuleClient.listMiscModules.mockRejectedValueOnce(new Error("backend unavailable"));

    const { result } = renderHook(() => useMiscToolsCatalog({ miscModuleClient }));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.modules).toEqual([]);
    expect(result.current.error).toBe("backend unavailable");

    miscModuleClient.importMiscModulePackage.mockRejectedValueOnce(new Error("bad package"));
    await act(async () => {
      await expect(result.current.importModule(new File(["bad"], "bad.zip"))).resolves.toBeUndefined();
    });

    expect(result.current.error).toBe("bad package");
  });

  it("keeps toggled modules mounted", async () => {
    const miscModuleClient = createClient();
    const { result } = renderHook(() => useMiscToolsCatalog({ miscModuleClient }));
    await waitFor(() => expect(result.current.loading).toBe(false));

    act(() => {
      result.current.toggleModule("custom-demo");
    });

    expect(result.current.expandedModules["custom-demo"]).toBe(true);
    expect(result.current.mountedModules["custom-demo"]).toBe(true);
  });
});
