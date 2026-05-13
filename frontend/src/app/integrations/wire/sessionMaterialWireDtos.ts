export interface SMB3SessionCandidateWireDTO extends Record<string, unknown> {
  session_id?: unknown;
  username?: unknown;
  domain?: unknown;
  nt_proof_str?: unknown;
  encrypted_session_key?: unknown;
  src?: unknown;
  dst?: unknown;
  frame_number?: unknown;
  timestamp?: unknown;
  complete?: unknown;
  display_label?: unknown;
}

export interface SMB3RandomSessionKeyResultWireDTO extends Record<string, unknown> {
  random_session_key?: unknown;
  message?: unknown;
}

export interface NTLMSessionMaterialWireDTO extends Record<string, unknown> {
  protocol?: unknown;
  transport?: unknown;
  frame_number?: unknown;
  timestamp?: unknown;
  src?: unknown;
  dst?: unknown;
  src_port?: unknown;
  dst_port?: unknown;
  direction?: unknown;
  username?: unknown;
  domain?: unknown;
  user_display?: unknown;
  challenge?: unknown;
  nt_proof_str?: unknown;
  encrypted_session_key?: unknown;
  session_id?: unknown;
  auth_header?: unknown;
  www_authenticate?: unknown;
  info?: unknown;
  complete?: unknown;
  display_label?: unknown;
}
