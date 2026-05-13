export interface InvestigationReportItemWireDTO extends Record<string, unknown> {
  title?: unknown;
  summary?: unknown;
  severity?: unknown;
  packet_id?: unknown;
  stream_id?: unknown;
  rule_id?: unknown;
  reason?: unknown;
  confidence?: unknown;
  caveats?: unknown;
  tags?: unknown;
}

export interface InvestigationReportWireDTO extends Record<string, unknown> {
  summary?: unknown;
  evidence?: unknown;
  details?: unknown;
  recommendations?: unknown;
}
