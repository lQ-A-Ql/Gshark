import type { MCPConfigWireDTO, MCPStatusWireDTO } from "../wire/mcpWireDtos";

export function asMCPConfig(config: MCPConfigWireDTO) {
  return {
    enabled: Boolean(config.enabled),
  };
}

export function asMCPStatus(status: MCPStatusWireDTO) {
  const config = (status.config ?? {}) as MCPConfigWireDTO;
  return {
    config: asMCPConfig(config),
    enabled: Boolean(status.enabled),
    endpoint: String(status.endpoint ?? ""),
    transport: String(status.transport ?? ""),
    authRequired: Boolean(status.auth_required),
    readOnly: Boolean(status.read_only),
    remoteSupported: Boolean(status.remote_supported),
    stdioSupported: Boolean(status.stdio_supported),
    lastError: String(status.last_error ?? "") || undefined,
  };
}
