import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DesktopTransportBinding } from "./bridgeTypes";

const mocks = vi.hoisted(() => ({
  createHttpBridge: vi.fn(),
  createDesktopBridge: vi.fn(),
}));

vi.mock("./httpBridge", () => ({
  createHttpBridge: mocks.createHttpBridge,
}));

vi.mock("./desktopBridge", () => ({
  createDesktopBridge: mocks.createDesktopBridge,
}));

describe("createBridge", () => {
  beforeEach(() => {
    mocks.createHttpBridge.mockReset();
    mocks.createDesktopBridge.mockReset();
    mocks.createHttpBridge.mockReturnValue({
      id: "http",
      getEvidenceWithFilter: vi.fn(),
      listObjects: vi.fn(),
      listThreatHits: vi.fn(),
    });
    mocks.createDesktopBridge.mockImplementation(() => ({
      id: "desktop",
    }));
  });

  it("uses http bridge when desktop binding is absent", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const bridge = createBridge({
      getDesktopAppBinding: () => undefined,
    });
    expect((bridge as unknown as { id: string }).id).toBe("http");
    expect(mocks.createDesktopBridge).not.toHaveBeenCalled();
  });

  it("uses desktop bridge when desktop binding exists", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const binding: DesktopTransportBinding = {
      BackendStatus: vi.fn(async () => "running"),
    };
    const bridge = createBridge({
      getDesktopAppBinding: () => binding,
    });
    expect((bridge as unknown as { id: string }).id).toBe("desktop");
    expect(mocks.createHttpBridge).not.toHaveBeenCalled();
  });

  it("passes only the Wails binding into desktop composition", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const binding: DesktopTransportBinding = {
      BackendStatus: vi.fn(async () => "running"),
    };

    const bridge = createBridge({
      getDesktopAppBinding: () => binding,
    });
    void (bridge as unknown as { id: string }).id;

    expect(mocks.createDesktopBridge).toHaveBeenCalledTimes(1);
    const args = mocks.createDesktopBridge.mock.calls[0]?.[0] as {
      desktopApp: DesktopTransportBinding;
    };
    expect(args.desktopApp).toBe(binding);
    expect("fallbackBridge" in args).toBe(false);
    expect(mocks.createHttpBridge).not.toHaveBeenCalled();
  });

  it("resolves a Wails binding that appears after bridge creation", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const bindingState: { binding?: DesktopTransportBinding } = {};
    const bridge = createBridge({
      getDesktopAppBinding: () => bindingState.binding,
    });

    expect((bridge as unknown as { id: string }).id).toBe("http");
    bindingState.binding = { BackendStatus: vi.fn(async () => "running") };

    expect((bridge as unknown as { id: string }).id).toBe("desktop");
    expect(mocks.createDesktopBridge).toHaveBeenCalledTimes(1);
  });
});
