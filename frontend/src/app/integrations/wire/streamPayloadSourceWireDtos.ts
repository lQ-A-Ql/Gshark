export interface StreamPayloadSourceWireDTO extends Record<string, unknown> {
  id?: unknown;
  method?: unknown;
  host?: unknown;
  uri?: unknown;
  packet_id?: unknown;
  stream_id?: unknown;
  source_type?: unknown;
  param_name?: unknown;
  payload?: unknown;
  preview?: unknown;
  confidence?: unknown;
  signals?: unknown;
  decoder_hints?: unknown;
  family_hint?: unknown;
  decoder_options_hint?: unknown;
  source_role?: unknown;
  content_type?: unknown;
  occurrence_count?: unknown;
  first_time?: unknown;
  last_time?: unknown;
  repeat_window_seconds?: unknown;
  related_packets?: unknown;
  rule_reasons?: unknown;
}
