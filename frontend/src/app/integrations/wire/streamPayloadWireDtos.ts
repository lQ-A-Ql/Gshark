export interface StreamChunkWireDTO extends Record<string, unknown> {
  packet_id?: unknown;
  direction?: unknown;
  body?: unknown;
}

export interface StreamLoadMetaWireDTO extends Record<string, unknown> {
  source?: unknown;
  loading?: unknown;
  cache_hit?: unknown;
  index_hit?: unknown;
  file_fallback?: unknown;
  tshark_ms?: unknown;
  override_count?: unknown;
}

export interface HttpStreamWireDTO extends Record<string, unknown> {
  stream_id?: unknown;
  from?: unknown;
  to?: unknown;
  request?: unknown;
  response?: unknown;
  chunks?: unknown;
  load_meta?: unknown;
}

export interface BinaryStreamWireDTO extends Record<string, unknown> {
  stream_id?: unknown;
  from?: unknown;
  to?: unknown;
  chunks?: unknown;
  next_cursor?: unknown;
  total?: unknown;
  has_more?: unknown;
  load_meta?: unknown;
}

export interface StreamPayloadUpdateWireDTO extends Record<string, unknown> {
  stream_id?: unknown;
  from?: unknown;
  to?: unknown;
  request?: unknown;
  response?: unknown;
  chunks?: unknown;
  load_meta?: unknown;
}
