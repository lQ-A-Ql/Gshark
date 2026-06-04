export interface C2DecryptedRecordWireDTO extends Record<string, unknown> {
  packet_id?: number;
  stream_id?: number;
  time?: string;
  direction?: string;
  algorithm?: string;
  key_status?: string;
  confidence?: number;
  plaintext_preview?: string;
  parsed?: Record<string, unknown>;
  raw_length?: number;
  decrypted_length?: number;
  tags?: string[];
  error?: string;
}

export interface C2DecryptResultWireDTO extends Record<string, unknown> {
  family?: string;
  status?: string;
  total_candidates?: number;
  decrypted_count?: number;
  failed_count?: number;
  records?: unknown[];
  notes?: string[];
}
