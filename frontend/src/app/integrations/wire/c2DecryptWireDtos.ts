export interface C2DecryptedRecordWireDTO extends Record<string, unknown> {
  packet_id?: unknown;
  stream_id?: unknown;
  time?: unknown;
  direction?: unknown;
  algorithm?: unknown;
  key_status?: unknown;
  confidence?: unknown;
  plaintext_preview?: unknown;
  parsed?: unknown;
  raw_length?: unknown;
  decrypted_length?: unknown;
  tags?: unknown;
  error?: unknown;
}

export interface C2DecryptResultWireDTO extends Record<string, unknown> {
  family?: unknown;
  status?: unknown;
  total_candidates?: unknown;
  decrypted_count?: unknown;
  failed_count?: unknown;
  records?: unknown;
  notes?: unknown;
}
