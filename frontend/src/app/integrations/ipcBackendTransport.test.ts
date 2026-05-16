import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DESKTOP_IPC_BLOB_MAX_BYTES,
  createIpcBackendTransport,
} from "./ipcBackendTransport";
import type { DesktopTransportBinding } from "./desktopTransportBinding";

vi.mock("../../../wailsjs/runtime", () => ({
  EventsOn: vi.fn(() => vi.fn()),
}));

describe("ipcBackendTransport", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends JSON requests through InvokeBackendJSON with desktop proxy metadata", async () => {
    const invoke = vi.fn(async (request: unknown) => {
      expect(request).toMatchObject({
        method: "POST",
        path: "/api/c2/decrypt",
        body_kind: "json",
        json_body: { port: 4444 },
      });
      return { ok: true };
    });
    const transport = createIpcBackendTransport({ InvokeBackendJSON: invoke } as DesktopTransportBinding);

    const payload = await transport.requestJSON<{ ok: boolean }>("/api/c2/decrypt", {
      method: "POST",
      body: JSON.stringify({ port: 4444 }),
    });

    expect(payload.ok).toBe(true);
    expect((payload as any).__backendRequestMeta).toMatchObject({
      transport: "desktop-ipc",
      endpoint: "/api/c2/decrypt",
      authState: "desktop-proxy",
    });
  });

  it("converts desktop blob responses back into Blob objects", async () => {
    const invoke = vi.fn(async () => ({
      data_base64: btoa("zip"),
      content_type: "application/zip",
      filename: "objects.zip",
      size: 3,
    }));
    const transport = createIpcBackendTransport({ InvokeBackendBlob: invoke } as DesktopTransportBinding);

    const blob = await transport.requestBlob("/api/objects/download", {
      method: "POST",
      body: JSON.stringify({ ids: [1] }),
    });

    expect(blob.type).toBe("application/zip");
    expect(await readBlobText(blob)).toBe("zip");
    expect(invoke).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        path: "/api/objects/download",
        body_kind: "json",
        json_body: { ids: [1] },
      }),
    );
  });

  it("converts FormData uploads to explicit multipart IPC parts", async () => {
    const invoke = vi.fn(async (request: unknown) => {
      const multipart = (request as { multipart?: Array<Record<string, unknown>> }).multipart ?? [];
      expect(multipart).toHaveLength(2);
      expect(multipart[0]).toMatchObject({
        name: "label",
        value: "decoder",
      });
      expect(multipart[1]).toMatchObject({
        name: "file",
        filename: "module.zip",
        content_type: "application/zip",
        data_base64: btoa("zip"),
      });
      return { module: { id: "decoder" } };
    });
    const form = new FormData();
    form.append("label", "decoder");
    form.append("file", new File(["zip"], "module.zip", { type: "application/zip" }));
    const transport = createIpcBackendTransport({ InvokeBackendJSON: invoke } as DesktopTransportBinding);

    await transport.requestJSON("/api/tools/misc/import", {
      method: "POST",
      body: form,
    });

    expect(invoke).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        path: "/api/tools/misc/import",
        body_kind: "multipart",
      }),
    );
  });

  it("surfaces IPC failures with endpoint context", async () => {
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: vi.fn(async () => {
        throw new Error("backend proxy timeout");
      }),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/analysis/industrial")).rejects.toThrow(
      "Wails IPC 数据面不可用：/api/analysis/industrial",
    );
  });

  it("rejects unsupported methods before calling the Wails binding", async () => {
    const invoke = vi.fn(async () => ({ ok: true }));
    const transport = createIpcBackendTransport({ InvokeBackendJSON: invoke } as DesktopTransportBinding);

    await expect(
      transport.requestJSON("/api/analysis/industrial", {
        method: "PATCH",
      }),
    ).rejects.toMatchObject({
      code: "invalid_request",
      endpoint: "/api/analysis/industrial",
      transport: "desktop-ipc",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("preserves AbortError for caller-side IPC cancellation", async () => {
    const invoke = vi.fn(async () => ({ ok: true }));
    const transport = createIpcBackendTransport({ InvokeBackendJSON: invoke } as DesktopTransportBinding);
    const controller = new AbortController();
    controller.abort();

    await expect(transport.requestJSON("/api/capture/status", { signal: controller.signal })).rejects.toMatchObject({
      name: "AbortError",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("times out pending IPC requests with a structured ipc_timeout error", async () => {
    vi.useFakeTimers();
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: vi.fn(async () => new Promise<unknown>(() => undefined)),
    } as DesktopTransportBinding);

    const request = transport.requestJSON("/api/capture/status");
    const expectation = expect(request).rejects.toMatchObject({
      code: "ipc_timeout",
      endpoint: "/api/capture/status",
      transport: "desktop-ipc",
    });
    await vi.advanceTimersByTimeAsync(15000);

    await expectation;
  });

  it("rejects oversized desktop blob responses before base64 decoding", async () => {
    const transport = createIpcBackendTransport({
      InvokeBackendBlob: vi.fn(async () => ({
        data_base64: "",
        content_type: "application/zip",
        size: DESKTOP_IPC_BLOB_MAX_BYTES + 1,
      })),
    } as DesktopTransportBinding);

    await expect(transport.requestBlob("/api/objects/download")).rejects.toMatchObject({
      code: "blob_too_large",
      endpoint: "/api/objects/download",
      transport: "desktop-ipc",
    });
  });
});

function readBlobText(blob: Blob): Promise<string> {
  if (typeof blob.text === "function") {
    return blob.text();
  }
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("read blob failed"));
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.readAsText(blob);
  });
}
