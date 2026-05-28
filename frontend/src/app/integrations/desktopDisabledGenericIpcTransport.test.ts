import { describe, expect, it, vi } from "vitest";
import { createDisabledGenericIpcBackendTransport } from "./desktopDisabledGenericIpcTransport";

vi.mock("../../../wailsjs/runtime", () => ({
  EventsOn: vi.fn(() => vi.fn()),
}));

describe("desktopDisabledGenericIpcTransport", () => {
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
});
