export interface APTScoreFactorWireDTO extends Record<string, unknown> {
  name?: unknown;
  weight?: unknown;
  direction?: unknown;
  source_module?: unknown;
  summary?: unknown;
}

export interface APTEvidenceRecordWireDTO extends Record<string, unknown> {
  packet_id?: unknown;
  stream_id?: unknown;
  time?: unknown;
  actor_id?: unknown;
  actor_name?: unknown;
  source_module?: unknown;
  family?: unknown;
  evidence_type?: unknown;
  evidence_value?: unknown;
  confidence?: unknown;
  source?: unknown;
  destination?: unknown;
  host?: unknown;
  uri?: unknown;
  sample_family?: unknown;
  campaign_stage?: unknown;
  transport_traits?: unknown;
  infrastructure_hints?: unknown;
  ttp_tags?: unknown;
  tags?: unknown;
  score_factors?: unknown;
  summary?: unknown;
  evidence?: unknown;
}

export interface APTActorProfileWireDTO extends Record<string, unknown> {
  id?: unknown;
  name?: unknown;
  aliases?: unknown;
  summary?: unknown;
  confidence?: unknown;
  evidence_count?: unknown;
  sample_families?: unknown;
  campaign_stages?: unknown;
  transport_traits?: unknown;
  infrastructure_hints?: unknown;
  related_c2_families?: unknown;
  ttp_tags?: unknown;
  score_factors?: unknown;
  notes?: unknown;
}

export interface APTAnalysisWireDTO extends Record<string, unknown> {
  total_evidence?: unknown;
  actors?: unknown;
  sample_families?: unknown;
  campaign_stages?: unknown;
  transport_traits?: unknown;
  infrastructure_hints?: unknown;
  related_c2_families?: unknown;
  profiles?: unknown;
  evidence?: unknown;
  notes?: unknown;
}
