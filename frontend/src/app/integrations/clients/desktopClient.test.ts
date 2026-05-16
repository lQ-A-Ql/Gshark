import { describe, expect, it, vi } from "vitest";
import { createDesktopClient, getLastBackendReadinessError } from "./desktopClient";

describe("createDesktopClient", () => {
  it("requires authenticated data-plane probes before reporting the backend as available", async () => {
    const requestMock = vi.fn(async (path: string) => {
      if (path === "/health") return { status: "ok" };
      if (path === "/api/runtime/identity") return { service: "gshark-sentinel" };
      if (path === "/api/capture/status") return { has_capture: false };
      throw new Error(`unexpected path ${path}`);
    });
    const request = requestMock as unknown as <T>(path: string, init?: RequestInit) => Promise<T>;
    const client = createDesktopClient(request, () => undefined);

    await expect(client.isAvailable()).resolves.toBe(true);

    expect(requestMock).toHaveBeenCalledWith("/health");
    expect(requestMock).toHaveBeenCalledWith("/api/runtime/identity");
    expect(requestMock).toHaveBeenCalledWith("/api/capture/status");
    expect(getLastBackendReadinessError()).toBe("");
  });

  it("reports health-only success as unavailable when the data plane fails", async () => {
    const requestMock = vi.fn(async (path: string) => {
      if (path === "/health") return { status: "ok" };
      throw new Error("后端鉴权失败：token 不匹配或已过期");
    });
    const request = requestMock as unknown as <T>(path: string, init?: RequestInit) => Promise<T>;
    const client = createDesktopClient(request, () => ({ BackendStatus: vi.fn(async () => "running") }));

    await expect(client.isAvailable()).resolves.toBe(false);

    expect(getLastBackendReadinessError()).toContain("HTTP 数据面不可用");
    expect(getLastBackendReadinessError()).toContain("token 不匹配");
  });
});
