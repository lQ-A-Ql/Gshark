import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DESKTOP_IPC_BLOB_MAX_BYTES,
  createDisabledGenericIpcBackendTransport,
  createIpcBackendTransport,
  withDesktopIpcControls,
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

  it("blocks generic MISC module import when the typed file-path import binding is available", async () => {
    const invoke = vi.fn(async (request: unknown) => {
      throw new Error(`generic import should not run: ${JSON.stringify(request)}`);
    });
    const form = new FormData();
    form.append("file", new File(["zip"], "module.zip", { type: "application/zip" }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invoke,
      ImportMiscModulePackageFromPath: vi.fn(),
    } as DesktopTransportBinding);

    await expect(
      transport.requestJSON("/api/tools/misc/import", {
        method: "POST",
        body: form,
      }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/tools/misc/import",
      transport: "desktop-ipc",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("allows browser-style generic MISC import only when native typed import is missing", async () => {
    const invoke = vi.fn(async () => ({ module: { id: "decoder" } }));
    const form = new FormData();
    form.append("file", new File(["zip"], "module.zip", { type: "application/zip" }));
    const transport = createIpcBackendTransport({ InvokeBackendJSON: invoke } as DesktopTransportBinding);

    await expect(
      transport.requestJSON("/api/tools/misc/import", {
        method: "POST",
        body: form,
      }),
    ).resolves.toMatchObject({ module: { id: "decoder" } });

    expect(invoke).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        path: "/api/tools/misc/import",
        body_kind: "multipart",
      }),
    );
  });

  it("reports disabled generic IPC with endpoint context while preserving Wails event subscription", async () => {
    const transport = createDisabledGenericIpcBackendTransport();

    await expect(transport.requestJSON("/api/objects")).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/objects",
      transport: "desktop-ipc",
    });
    await expect(transport.requestBlob("/api/objects/download")).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/objects/download",
      transport: "desktop-ipc",
    });
    await expect(transport.requestText("/api/tools/winrm-decrypt/export")).rejects.toMatchObject({
      code: "generic_ipc_disabled",
      endpoint: "/api/tools/winrm-decrypt/export",
      transport: "desktop-ipc",
    });

    const unsubscribe = transport.subscribeEvents({});
    unsubscribe();
    expect(unsubscribe).toEqual(expect.any(Function));
  });

  it("allows generic IPC for MISC import when the typed binding is missing", async () => {
    const invoke = vi.fn(async () => ({ ok: true }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invoke,
      ListMiscModules: vi.fn(),
      RunMiscModulePackage: vi.fn(),
    } as DesktopTransportBinding);

    await expect(
      transport.requestJSON("/api/tools/misc/import", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    ).resolves.toMatchObject({
      ok: true,
    });
    expect(invoke).toHaveBeenCalledTimes(1);
  });

  it("blocks generic MISC import JSON when the typed file-path import binding is available", async () => {
    const invoke = vi.fn(async () => ({ ok: true }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invoke,
      ImportMiscModulePackageFromPath: vi.fn(),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/tools/misc/import", { method: "POST", body: "{}" })).rejects.toMatchObject(
      {
        code: "typed_binding_required",
        endpoint: "/api/tools/misc/import",
        transport: "desktop-ipc",
      },
    );
    expect(invoke).not.toHaveBeenCalled();
  });

  it("blocks generic MISC module invoke when the typed binding is available", async () => {
    const invoke = vi.fn(async () => ({ message: "ok" }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invoke,
      RunMiscModulePackage: vi.fn(async () => ({ message: "ok" })),
    } as DesktopTransportBinding);

    await expect(
      transport.requestJSON("/api/tools/misc/packages/demo/invoke", {
        method: "POST",
        body: JSON.stringify({ values: {} }),
      }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/tools/misc/packages/demo/invoke",
      transport: "desktop-ipc",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("blocks generic MISC package delete when the typed binding is available", async () => {
    const invoke = vi.fn(async () => ({ deleted: true }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invoke,
      DeleteMiscModulePackage: vi.fn(async () => ({ deleted: true })),
    } as DesktopTransportBinding);

    await expect(
      transport.requestJSON("/api/tools/misc/packages/demo.module", {
        method: "DELETE",
      }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/tools/misc/packages/demo.module",
      transport: "desktop-ipc",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("blocks generic MISC module listing when the typed binding is available", async () => {
    const invoke = vi.fn(async () => []);
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invoke,
      ListMiscModules: vi.fn(async () => []),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/tools/misc/modules")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/tools/misc/modules",
      transport: "desktop-ipc",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("blocks generic IPC when a migrated typed binding is available for that route", async () => {
    const invoke = vi.fn(async () => ({ total_attempts: 0 }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invoke,
      GetHTTPLoginAnalysis: vi.fn(async () => ({ total_attempts: 0 })),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/tools/http-login-analysis")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/tools/http-login-analysis",
      transport: "desktop-ipc",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("blocks generic blob IPC when a migrated typed blob binding is available", async () => {
    const invoke = vi.fn(async () => ({
      data_base64: btoa("zip"),
      content_type: "application/zip",
      size: 3,
    }));
    const transport = createIpcBackendTransport({
      InvokeBackendBlob: invoke,
      DownloadObjectsZip: vi.fn(),
    } as DesktopTransportBinding);

    await expect(transport.requestBlob("/api/objects/download")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/objects/download",
      transport: "desktop-ipc",
    });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("blocks generic media JSON and blob IPC when migrated typed media bindings are available", async () => {
    const invokeJSON = vi.fn(async () => ({ total_media_packets: 0 }));
    const invokeBlob = vi.fn(async () => ({
      data_base64: btoa("media"),
      content_type: "audio/wav",
      size: 5,
    }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invokeJSON,
      InvokeBackendBlob: invokeBlob,
      GetMediaAnalysis: vi.fn(),
      TranscribeMediaArtifact: vi.fn(),
      GetMediaBatchTranscriptionStatus: vi.fn(),
      DownloadMediaArtifact: vi.fn(),
      GetMediaPlaybackBlob: vi.fn(),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/analysis/media?refresh=1")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/media?refresh=1",
      transport: "desktop-ipc",
    });
    await expect(
      transport.requestJSON("/api/analysis/media/transcribe", {
        method: "POST",
        body: JSON.stringify({ token: "tok" }),
      }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/media/transcribe",
      transport: "desktop-ipc",
    });
    await expect(transport.requestJSON("/api/analysis/media/transcribe/batch")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/media/transcribe/batch",
      transport: "desktop-ipc",
    });
    await expect(transport.requestBlob("/api/analysis/media/export?token=tok")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/media/export?token=tok",
      transport: "desktop-ipc",
    });
    await expect(transport.requestBlob("/api/analysis/media/play?token=tok")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/media/play?token=tok",
      transport: "desktop-ipc",
    });
    expect(invokeJSON).not.toHaveBeenCalled();
    expect(invokeBlob).not.toHaveBeenCalled();
  });

  it("blocks generic packet locate and detail IPC when migrated typed packet bindings are available", async () => {
    const invokeJSON = vi.fn(async () => ({ packet_id: 42, found: true }));
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invokeJSON,
      LocatePacketPage: vi.fn(),
      GetPacket: vi.fn(),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/packets/locate?id=42&limit=50&filter=http")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/packets/locate?id=42&limit=50&filter=http",
      transport: "desktop-ipc",
    });
    await expect(transport.requestJSON("/api/packet?id=42")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/packet?id=42",
      transport: "desktop-ipc",
    });
    expect(invokeJSON).not.toHaveBeenCalled();
  });

  it("blocks generic hunting IPC when migrated typed hunting bindings are available", async () => {
    const invokeJSON = vi.fn(async () => []);
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invokeJSON,
      ListThreatHits: vi.fn(),
      GetHuntingRuntimeConfig: vi.fn(),
      UpdateHuntingRuntimeConfig: vi.fn(),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/hunting?prefix=flag%7B")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/hunting?prefix=flag%7B",
      transport: "desktop-ipc",
    });
    await expect(transport.requestJSON("/api/hunting/config")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/hunting/config",
      transport: "desktop-ipc",
    });
    await expect(
      transport.requestJSON("/api/hunting/config", {
        method: "POST",
        body: JSON.stringify({ prefixes: ["flag{"] }),
      }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/hunting/config",
      transport: "desktop-ipc",
    });
    expect(invokeJSON).not.toHaveBeenCalled();
  });

  it("blocks generic vehicle DBC IPC when migrated typed DBC bindings are available", async () => {
    const invokeJSON = vi.fn(async () => []);
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invokeJSON,
      ListVehicleDBCProfiles: vi.fn(),
      AddVehicleDBC: vi.fn(),
      RemoveVehicleDBC: vi.fn(),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/analysis/vehicle/dbc")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/vehicle/dbc",
      transport: "desktop-ipc",
    });
    await expect(
      transport.requestJSON("/api/analysis/vehicle/dbc", {
        method: "POST",
        body: JSON.stringify({ path: "truck.dbc" }),
      }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/vehicle/dbc",
      transport: "desktop-ipc",
    });
    await expect(
      transport.requestJSON("/api/analysis/vehicle/dbc?path=truck.dbc", {
        method: "DELETE",
      }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/analysis/vehicle/dbc?path=truck.dbc",
      transport: "desktop-ipc",
    });
    expect(invokeJSON).not.toHaveBeenCalled();
  });

  it("blocks generic plugin IPC when migrated typed plugin bindings are available", async () => {
    const invokeJSON = vi.fn(async () => []);
    const transport = createIpcBackendTransport({
      InvokeBackendJSON: invokeJSON,
      ListPlugins: vi.fn(),
      GetPluginSource: vi.fn(),
      SavePluginSource: vi.fn(),
      AddPlugin: vi.fn(),
      DeletePlugin: vi.fn(),
      TogglePlugin: vi.fn(),
      SetPluginsEnabled: vi.fn(),
    } as DesktopTransportBinding);

    await expect(transport.requestJSON("/api/plugins")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/plugins",
      transport: "desktop-ipc",
    });
    await expect(transport.requestJSON("/api/plugins/source?id=echo")).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/plugins/source?id=echo",
      transport: "desktop-ipc",
    });
    await expect(
      transport.requestJSON("/api/plugins/source", { method: "POST", body: JSON.stringify({ id: "echo" }) }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/plugins/source",
      transport: "desktop-ipc",
    });
    await expect(
      transport.requestJSON("/api/plugins/add", { method: "POST", body: JSON.stringify({ id: "new" }) }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/plugins/add",
      transport: "desktop-ipc",
    });
    await expect(transport.requestJSON("/api/plugins/delete?id=old", { method: "POST" })).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/plugins/delete?id=old",
      transport: "desktop-ipc",
    });
    await expect(transport.requestJSON("/api/plugins/toggle?id=echo", { method: "POST" })).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/plugins/toggle?id=echo",
      transport: "desktop-ipc",
    });
    await expect(
      transport.requestJSON("/api/plugins/bulk", { method: "POST", body: JSON.stringify({ ids: ["echo"] }) }),
    ).rejects.toMatchObject({
      code: "typed_binding_required",
      endpoint: "/api/plugins/bulk",
      transport: "desktop-ipc",
    });
    expect(invokeJSON).not.toHaveBeenCalled();
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

  it("does not pass an implicit undefined argument to typed zero-argument Wails calls", async () => {
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
