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

export interface WinRMDecryptResultWireDTO extends Record<string, unknown> {
  result_id?: unknown;
  capture_name?: unknown;
  port?: unknown;
  auth_mode?: unknown;
  preview_text?: unknown;
  preview_truncated?: unknown;
  line_count?: unknown;
  frame_count?: unknown;
  error_frame_count?: unknown;
  extracted_frame_count?: unknown;
  export_filename?: unknown;
  message?: unknown;
}
