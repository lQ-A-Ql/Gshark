export interface ShiroRememberMeCandidateWireDTO extends Record<string, unknown> {
  packet_id?: unknown;
  stream_id?: unknown;
  time?: unknown;
  src?: unknown;
  dst?: unknown;
  host?: unknown;
  path?: unknown;
  source_header?: unknown;
  cookie_name?: unknown;
  cookie_value?: unknown;
  cookie_preview?: unknown;
  decode_ok?: unknown;
  encrypted_length?: unknown;
  aes_block_aligned?: unknown;
  possible_cbc?: unknown;
  possible_gcm?: unknown;
  key_results?: unknown;
  hit_count?: unknown;
  notes?: unknown;
}

export interface ShiroKeyResultWireDTO extends Record<string, unknown> {
  label?: unknown;
  base64?: unknown;
  algorithm?: unknown;
  hit?: unknown;
  payload_class?: unknown;
  preview?: unknown;
  reason?: unknown;
}
