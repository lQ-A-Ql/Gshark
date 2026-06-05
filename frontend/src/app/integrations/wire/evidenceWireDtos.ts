export interface EvidenceListWireDTO extends Record<string, unknown> {
  records?: unknown;
  total?: unknown;
  notes?: unknown;
}

export interface UnifiedEvidenceRecordWireDTO extends Record<string, unknown> {
  id?: unknown;
  module?: unknown;
  source_module?: unknown;
  packet_id?: unknown;
  stream_id?: unknown;
  family?: unknown;
  feature?: unknown;
  entity_type?: unknown;
  protocol?: unknown;
  version?: unknown;
  display_name?: unknown;
  rule_id?: unknown;
  rule_name?: unknown;
  playbook_id?: unknown;
  playbook_name?: unknown;
  ioc_type?: unknown;
  ioc_value?: unknown;
  ja3_hash?: unknown;
  ja3s_hash?: unknown;
  metadata?: unknown;
  actor_id?: unknown;
  actor_name?: unknown;
  source_type?: unknown;
  summary?: unknown;
  value?: unknown;
  confidence?: unknown;
  severity?: unknown;
  source?: unknown;
  destination?: unknown;
  host?: unknown;
  uri?: unknown;
  tags?: unknown;
  caveats?: unknown;
}

export interface ExtractedObjectWireDTO extends Record<string, unknown> {
  id?: unknown;
  packet_id?: unknown;
  name?: unknown;
  size_bytes?: unknown;
  mime?: unknown;
  magic?: unknown;
  source?: unknown;
}
