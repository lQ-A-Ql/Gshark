export interface MCPConfigWireDTO extends Record<string, unknown> {
  enabled?: unknown;
}

export interface MCPStatusWireDTO extends Record<string, unknown> {
  config?: unknown;
  enabled?: unknown;
  endpoint?: unknown;
  transport?: unknown;
  auth_required?: unknown;
  read_only?: unknown;
  remote_supported?: unknown;
  stdio_supported?: unknown;
  last_error?: unknown;
}
