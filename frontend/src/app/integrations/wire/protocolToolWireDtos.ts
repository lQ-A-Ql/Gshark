export interface HTTPLoginAnalysisWireDTO extends Record<string, unknown> {
  total_attempts?: unknown;
  candidate_endpoints?: unknown;
  success_count?: unknown;
  failure_count?: unknown;
  uncertain_count?: unknown;
  bruteforce_count?: unknown;
  endpoints?: unknown;
  attempts?: unknown;
  notes?: unknown;
  report?: unknown;
}

export interface SMTPAnalysisWireDTO extends Record<string, unknown> {
  session_count?: unknown;
  message_count?: unknown;
  auth_count?: unknown;
  attachment_hint_count?: unknown;
  sessions?: unknown;
  notes?: unknown;
  report?: unknown;
}

export interface MySQLAnalysisWireDTO extends Record<string, unknown> {
  session_count?: unknown;
  login_count?: unknown;
  query_count?: unknown;
  error_count?: unknown;
  resultset_count?: unknown;
  sessions?: unknown;
  notes?: unknown;
  report?: unknown;
}

export interface ShiroRememberMeAnalysisWireDTO extends Record<string, unknown> {
  candidate_count?: unknown;
  hit_count?: unknown;
  candidates?: unknown;
  notes?: unknown;
  report?: unknown;
}
