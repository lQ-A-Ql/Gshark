export interface CaptureStatusWireDTO extends Record<string, unknown> {
  file_path?: unknown;
  filePath?: unknown;
  has_capture?: unknown;
  hasCapture?: unknown;
  packet_count?: unknown;
  packetCount?: unknown;
}

export interface PacketWireDTO extends Record<string, unknown> {
  id?: unknown;
  timestamp?: unknown;
  source_ip?: unknown;
  source_port?: unknown;
  dest_ip?: unknown;
  dest_port?: unknown;
  protocol?: unknown;
  display_protocol?: unknown;
  length?: unknown;
  info?: unknown;
  payload?: unknown;
  raw_hex?: unknown;
  stream_id?: unknown;
  ip_header_len?: unknown;
  l4_header_len?: unknown;
  color_features?: unknown;
}

export interface PacketsPageWireDTO extends Record<string, unknown> {
  items?: unknown;
  next_cursor?: unknown;
  total?: unknown;
  has_more?: unknown;
  filtering?: unknown;
}

export interface PacketLocateWireDTO extends Record<string, unknown> {
  packet_id?: unknown;
  cursor?: unknown;
  total?: unknown;
  found?: unknown;
}
