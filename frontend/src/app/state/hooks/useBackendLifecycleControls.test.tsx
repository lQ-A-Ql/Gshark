import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import type { DecryptionConfig } from "../../core/types";
import { useBackendLifecycleControls } from "./useBackendLifecycleControls";

const bridgeMocks = vi.hoisted(() => ({
  updateTLSConfig: vi.fn(),
}));

vi.mock("../../integrations/backendClients", () => ({
  backendClients: { securityMaterial: { updateTLSConfig: bridgeMocks.updateTLSConfig } },
}));

function renderControls(backendConnected: boolean) {
  const setTSharkPathImpl = vi.fn().mockResolvedValue(undefined);
  const refreshToolRuntimeSnapshotImpl = vi.fn().mockResolvedValue(null);
  const saveToolRuntimeConfigImpl = vi.fn().mockResolvedValue({});
  const result = renderHook(() => {
    const [backendStatus, setBackendStatus] = useState("");
    const [decryptionConfig, setDecryptionConfig] = useState<DecryptionConfig>({
      sslKeyLogPath: "C:/old.log",
      privateKeyPath: "C:/key.pem",
      privateKeyIpPort: "10.0.0.1:443",
    });
    const controls = useBackendLifecycleControls({
      backendConnected,
      setBackendStatus,
      setDecryptionConfig,
      setTSharkPathImpl,
      refreshToolRuntimeSnapshotImpl,
      saveToolRuntimeConfigImpl,
    });
    return { ...controls, backendStatus, decryptionConfig };
  });
  return { ...result, refreshToolRuntimeSnapshotImpl, saveToolRuntimeConfigImpl, setTSharkPathImpl };
}

describe("useBackendLifecycleControls", () => {
  beforeEach(() => {
    bridgeMocks.updateTLSConfig.mockReset();
  });

  it("merges TLS config and syncs it when backend is connected", () => {
    bridgeMocks.updateTLSConfig.mockResolvedValue(undefined);
    const { result } = renderControls(true);

    act(() => result.current.updateDecryptionConfig({ sslKeyLogPath: "D:/next.log" }));

    expect(result.current.decryptionConfig.sslKeyLogPath).toBe("D:/next.log");
    expect(bridgeMocks.updateTLSConfig).toHaveBeenCalledWith({
      sslKeyLogPath: "D:/next.log",
      privateKeyPath: "C:/key.pem",
      privateKeyIpPort: "10.0.0.1:443",
    });
  });

  it("keeps TLS config local when backend is disconnected", () => {
    const { result } = renderControls(false);

    act(() => result.current.updateDecryptionConfig({ privateKeyPath: "D:/offline.pem" }));

    expect(result.current.decryptionConfig.privateKeyPath).toBe("D:/offline.pem");
    expect(bridgeMocks.updateTLSConfig).not.toHaveBeenCalled();
  });
});
