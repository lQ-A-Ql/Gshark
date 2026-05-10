import { describe, expect, it, vi } from "vitest";
import type { BackendBridge, DesktopTransportBinding } from "./bridgeTypes";

vi.mock("./httpBridge", () => ({
  createHttpBridge: vi.fn(() => ({ id: "http" })),
}));

vi.mock("./desktopBridge", () => ({
  createDesktopBridge: vi.fn(({ fallbackBridge }: { fallbackBridge: BackendBridge }) => ({
    id: "desktop",
    fallbackBridge,
  })),
}));

describe("createBridge", () => {
  it("uses http bridge when desktop binding is absent", async () => {
    const { createBridge } = await import("./bridgeFactory");
    const bridge = createBridge({
      getDesktopAppBinding: () => undefined,
    });
    expect((bridge as any).id).toBe("http");
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
});
