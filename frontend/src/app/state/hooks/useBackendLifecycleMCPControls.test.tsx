import { act, renderHook } from "@testing-library/react";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { MCPStatus } from "../../core/types";
import { useBackendLifecycleMCPControls } from "./useBackendLifecycleMCPControls";

const bridgeMocks = vi.hoisted(() => ({
  getMCPStatus: vi.fn(),
  updateMCPConfig: vi.fn(),
}));

vi.mock("../../integrations/backendClients", () => ({
  backendClients: {
    runtime: {
      getMCPStatus: bridgeMocks.getMCPStatus,
      updateMCPConfig: bridgeMocks.updateMCPConfig,
    },
  },
}));

const defaultMCPStatus: MCPStatus = {
  config: { enabled: true },
  enabled: true,
  endpoint: "http://127.0.0.1:17891/api/mcp",
  transport: "streamable-http",
  authRequired: true,
  readOnly: true,
  remoteSupported: false,
  stdioSupported: false,
};

function renderMCPControls(backendConnected: boolean) {
  return renderHook(() => {
    const [mcpStatus, setMCPStatus] = useState<MCPStatus | null>(null);
    const controls = useBackendLifecycleMCPControls({
      backendConnected,
      setMCPStatus,
    });
    return { ...controls, mcpStatus };
  });
}

describe("useBackendLifecycleMCPControls", () => {
  beforeEach(() => {
    bridgeMocks.getMCPStatus.mockReset();
    bridgeMocks.updateMCPConfig.mockReset();
  });

  it("refreshes MCP status when backend is connected", async () => {
    bridgeMocks.getMCPStatus.mockResolvedValue(defaultMCPStatus);
    const { result } = renderMCPControls(true);

    await act(async () => {
      await result.current.refreshMCPStatus();
    });

    expect(bridgeMocks.getMCPStatus).toHaveBeenCalledTimes(1);
    expect(result.current.mcpStatus).toEqual(defaultMCPStatus);
  });

  it("saves MCP config and stores the returned status", async () => {
    bridgeMocks.updateMCPConfig.mockResolvedValue({ ...defaultMCPStatus, config: { enabled: false }, enabled: false });
    const { result } = renderMCPControls(true);

    await act(async () => {
      await result.current.saveMCPConfig({ enabled: false });
    });

    expect(bridgeMocks.updateMCPConfig).toHaveBeenCalledWith({ enabled: false });
    expect(result.current.mcpStatus).toMatchObject({ enabled: false, config: { enabled: false } });
  });
});
