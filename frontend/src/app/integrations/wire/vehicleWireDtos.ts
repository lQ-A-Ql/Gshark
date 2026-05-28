export interface VehicleAnalysisWireDTO extends Record<string, unknown> {
  total_vehicle_packets?: unknown;
  protocols?: unknown;
  conversations?: unknown;
  can?: unknown;
  j1939?: unknown;
  doip?: unknown;
  uds?: unknown;
  recommendations?: unknown;
  report?: unknown;
}

export interface DBCProfileWireDTO extends Record<string, unknown> {
  path?: unknown;
  name?: unknown;
  message_count?: unknown;
  signal_count?: unknown;
}

export interface DecryptionConfigWireDTO extends Record<string, unknown> {
  ssl_key_log_file?: unknown;
  rsa_private_key?: unknown;
  target_ip_port?: unknown;
}
