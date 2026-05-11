import { describe, expect, it } from "vitest";

import { createBackendClients } from "./bridgeDomains";
import type { BackendBridge } from "./bridgeTypes";

describe("createBackendClients", () => {
  it("projects the compatibility bridge into domain clients", () => {
    const bridge = {} as BackendBridge;
    const clients = createBackendClients(bridge);

    expect(clients.runtime).toBe(bridge);
    expect(clients.capture).toBe(bridge);
    expect(clients.packet).toBe(bridge);
    expect(clients.stream).toBe(bridge);
    expect(clients.analysis).toBe(bridge);
    expect(clients.evidence).toBe(bridge);
    expect(clients.media).toBe(bridge);
    expect(clients.plugin).toBe(bridge);
    expect(clients.securityMaterial).toBe(bridge);
    expect(clients.miscModule).toBe(bridge);
  });
});
