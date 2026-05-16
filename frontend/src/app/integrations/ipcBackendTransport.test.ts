import { describe, expect, it, vi } from "vitest";
import { createIpcBackendTransport } from "./ipcBackendTransport";
import type { DesktopTransportBinding } from "./desktopTransportBinding";

vi.mock("../../../wailsjs/runtime", () => ({
  EventsOn: vi.fn(() => vi.fn()),
}));

describe("ipcBackendTransport", () => {
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
