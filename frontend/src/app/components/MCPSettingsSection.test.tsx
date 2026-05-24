import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { MCPStatus } from "../core/types";
import { MCPSettingsSection } from "./MCPSettingsSection";

const mcpStatus: MCPStatus = {
  config: { enabled: true },
  enabled: true,
  endpoint: "http://127.0.0.1:17891/api/mcp",
  transport: "streamable-http",
  authRequired: true,
  readOnly: true,
  remoteSupported: false,
  stdioSupported: false,
  lastError: "none",
};

describe("MCPSettingsSection", () => {
  it("renders MCP settings and toggles the local endpoint switch", () => {
    const onToggleEnabled = vi.fn();
    const onRefresh = vi.fn();
    const onCopyEndpoint = vi.fn();
    const onCopyToken = vi.fn();

    render(
      <MCPSettingsSection
        backendConnected
        busy={false}
        mcpBusy={false}
        mcpStatus={mcpStatus}
        mcpNotice="MCP 就绪"
        authToken="abcd1234efgh5678"
        tokenAvailable
        tokenBusy={false}
        onRefresh={onRefresh}
        onToggleEnabled={onToggleEnabled}
        onCopyEndpoint={onCopyEndpoint}
        onCopyToken={onCopyToken}
      />,
    );

    expect(screen.getByText("MCP 本地接口")).toBeInTheDocument();
    expect(screen.getByText("http://127.0.0.1:17891/api/mcp")).toBeInTheDocument();
    expect(screen.getByText("streamable-http")).toBeInTheDocument();
    expect(screen.getByText("abcd12...5678")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox"));
    expect(onToggleEnabled).toHaveBeenCalledWith(false);

    fireEvent.click(screen.getByRole("button", { name: /复制端点/ }));
    fireEvent.click(screen.getByRole("button", { name: /复制 Token/ }));
    fireEvent.click(screen.getByRole("button", { name: /刷新 MCP 状态/ }));
    expect(onCopyEndpoint).toHaveBeenCalledTimes(1);
    expect(onCopyToken).toHaveBeenCalledTimes(1);
    expect(onRefresh).toHaveBeenCalledTimes(1);
  });
});
