import { beforeEach, describe, expect, it, vi } from "vitest";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

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
    mocks.createDesktopBridge.mockImplementation(({ fallbackBridge }: { fallbackBridge: BackendBridge }) => ({
      id: "desktop",
      fallbackBridge,
    }));
  });

  it("uses http bridge when desktop binding is absent", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const bridge = createBridge({
      getDesktopAppBinding: () => undefined,
    });
    expect((bridge as any).id).toBe("http");
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
    expect((bridge as any).id).toBe("desktop");
    expect((bridge as any).fallbackBridge.id).toBe("http");
  });

  it("passes the report/evidence-capable http bridge into desktop composition", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const binding: DesktopTransportBinding = {
      BackendStatus: vi.fn(async () => "running"),
    };

    const bridge = createBridge({
      getDesktopAppBinding: () => binding,
    });
    void (bridge as any).id;

    expect(mocks.createDesktopBridge).toHaveBeenCalledTimes(1);
    const args = mocks.createDesktopBridge.mock.calls[0]?.[0] as {
      fallbackBridge: BackendBridge;
      desktopApp: DesktopTransportBinding;
    };
    expect(args.desktopApp).toBe(binding);
    expect(typeof (args.fallbackBridge as any).getEvidenceWithFilter).toBe("function");
    expect(typeof (args.fallbackBridge as any).listObjects).toBe("function");
    expect(typeof (args.fallbackBridge as any).listThreatHits).toBe("function");
  });

  it("resolves a Wails binding that appears after bridge creation", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const bindingState: { binding?: DesktopTransportBinding } = {};
    const bridge = createBridge({
      getDesktopAppBinding: () => bindingState.binding,
    });

    expect((bridge as any).id).toBe("http");
    bindingState.binding = { BackendStatus: vi.fn(async () => "running") };

    expect((bridge as any).id).toBe("desktop");
    expect(mocks.createDesktopBridge).toHaveBeenCalledTimes(1);
  });
});
