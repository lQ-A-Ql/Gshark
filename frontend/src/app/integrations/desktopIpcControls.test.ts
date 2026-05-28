import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DESKTOP_IPC_BLOB_MAX_BYTES,
  assertDesktopBlobWithinLimit,
  withDesktopIpcControls,
} from "./desktopIpcControls";

describe("desktopIpcControls", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not pass an implicit undefined argument to zero-argument Wails calls", async () => {
    const operation = vi.fn(async (...args: unknown[]) => {
      expect(args).toEqual([]);
      return { ok: true };
    });

    await expect(
      withDesktopIpcControls(operation, {
        endpoint: "DesktopApp.GetToolRuntimeSnapshotFast",
        responseKind: "typed-ipc",
        timeoutMs: 1000,
      }),
    ).resolves.toEqual({ ok: true });

    expect(operation).toHaveBeenCalledWith();
  });

  it("preserves AbortError for caller-side IPC cancellation", async () => {
    const operation = vi.fn(async () => ({ ok: true }));
    const controller = new AbortController();
    controller.abort();

    await expect(
      withDesktopIpcControls(operation, {
        endpoint: "/api/capture/status",
        responseKind: "typed-ipc",
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(operation).not.toHaveBeenCalled();
  });

  it("times out pending IPC requests with a structured ipc_timeout error", async () => {
    vi.useFakeTimers();

    const request = withDesktopIpcControls(async () => new Promise<unknown>(() => undefined), {
      endpoint: "/api/capture/status",
      responseKind: "typed-ipc",
      timeoutMs: 15000,
    });
    const expectation = expect(request).rejects.toMatchObject({
      code: "ipc_timeout",
      endpoint: "/api/capture/status",
      transport: "desktop-ipc",
    });
    await vi.advanceTimersByTimeAsync(15000);

    await expectation;
  });

  it("surfaces IPC failures with endpoint context", async () => {
    await expect(
      withDesktopIpcControls(
        async () => {
          throw new Error("backend proxy timeout");
        },
        {
          endpoint: "/api/analysis/industrial",
          responseKind: "typed-ipc",
          timeoutMs: 1000,
        },
      ),
    ).rejects.toThrow("Wails IPC 数据面不可用：/api/analysis/industrial");
  });

  it("rejects oversized desktop blob responses before base64 decoding", () => {
    expect(() =>
      assertDesktopBlobWithinLimit(
        {
          data_base64: "",
          size: DESKTOP_IPC_BLOB_MAX_BYTES + 1,
        },
        "/api/objects/download",
      ),
    ).toThrow("桌面 IPC blob 响应过大：/api/objects/download 超过 50MB");
  });
});
