export interface StreamDecodeResultWireDTO extends Record<string, unknown> {
  decoder?: unknown;
  summary?: unknown;
  text?: unknown;
  bytes_hex?: unknown;
  encoding?: unknown;
  confidence?: unknown;
  warnings?: unknown;
  signals?: unknown;
  attempt_errors?: unknown;
}

export interface StreamPayloadCandidateWireDTO extends Record<string, unknown> {
  id?: unknown;
  label?: unknown;
  kind?: unknown;
  param_name?: unknown;
  value?: unknown;
  preview?: unknown;
  confidence?: unknown;
  decoder_hints?: unknown;
  fingerprints?: unknown;
  family_hint?: unknown;
  decoder_options_hint?: unknown;
  source_role?: unknown;
}

export interface StreamPayloadInspectionWireDTO extends Record<string, unknown> {
  normalized_payload?: unknown;
  candidates?: unknown;
  suggested_candidate_id?: unknown;
  suggested_decoder?: unknown;
  suggested_family?: unknown;
  confidence?: unknown;
  reasons?: unknown;
}
