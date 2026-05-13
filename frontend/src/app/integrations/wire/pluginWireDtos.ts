export interface DBCProfileWireDTO extends Record<string, unknown> {
  path?: unknown;
  name?: unknown;
  message_count?: unknown;
  signal_count?: unknown;
}

export interface PluginItemWireDTO extends Record<string, unknown> {
  id?: unknown;
  name?: unknown;
  version?: unknown;
  tag?: unknown;
  author?: unknown;
  enabled?: unknown;
  entry?: unknown;
  runtime?: unknown;
  capabilities?: unknown;
}

export interface PluginSourceWireDTO extends Record<string, unknown> {
  id?: unknown;
  config_path?: unknown;
  config_content?: unknown;
  logic_path?: unknown;
  logic_content?: unknown;
  entry?: unknown;
}

export interface DecryptionConfigWireDTO extends Record<string, unknown> {
  ssl_key_log_file?: unknown;
  rsa_private_key?: unknown;
  target_ip_port?: unknown;
}
