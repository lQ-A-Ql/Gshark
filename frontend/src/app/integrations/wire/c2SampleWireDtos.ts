export interface C2ScoreFactorWireDTO extends Record<string, unknown> {
  name?: unknown;
  weight?: unknown;
  direction?: unknown;
  summary?: unknown;
}

export interface C2IndicatorRecordWireDTO extends Record<string, unknown> {
  packet_id?: unknown;
  stream_id?: unknown;
  time?: unknown;
  family?: unknown;
  channel?: unknown;
  source?: unknown;
  destination?: unknown;
  host?: unknown;
  uri?: unknown;
  method?: unknown;
  indicator_type?: unknown;
  indicator_value?: unknown;
  confidence?: unknown;
  summary?: unknown;
  evidence?: unknown;
  tags?: unknown;
  actor_hints?: unknown;
  sample_family?: unknown;
  campaign_stage?: unknown;
  transport_traits?: unknown;
  infrastructure_hints?: unknown;
  ttp_tags?: unknown;
  attribution_confidence?: unknown;
}

export interface C2BeaconPatternWireDTO extends Record<string, unknown> {
  name?: unknown;
  value?: unknown;
  confidence?: unknown;
  summary?: unknown;
}

export interface C2HTTPEndpointAggregateWireDTO extends Record<string, unknown> {
  host?: unknown;
  uri?: unknown;
  channel?: unknown;
  total?: unknown;
  get_count?: unknown;
  post_count?: unknown;
  methods?: unknown;
  first_time?: unknown;
  last_time?: unknown;
  avg_interval?: unknown;
  jitter?: unknown;
  intervals?: unknown;
  streams?: unknown;
  packets?: unknown;
  representative_packet?: unknown;
  confidence?: unknown;
  signal_tags?: unknown;
  score_factors?: unknown;
  summary?: unknown;
}

export interface C2DNSAggregateWireDTO extends Record<string, unknown> {
  qname?: unknown;
  total?: unknown;
  max_label_length?: unknown;
  query_types?: unknown;
  txt_count?: unknown;
  null_count?: unknown;
  cname_count?: unknown;
  request_count?: unknown;
  response_count?: unknown;
  first_time?: unknown;
  last_time?: unknown;
  avg_interval?: unknown;
  jitter?: unknown;
  intervals?: unknown;
  packets?: unknown;
  confidence?: unknown;
  summary?: unknown;
}

export interface C2StreamAggregateWireDTO extends Record<string, unknown> {
  stream_id?: unknown;
  protocol?: unknown;
  total_packets?: unknown;
  arch_markers?: unknown;
  length_prefix_count?: unknown;
  short_packets?: unknown;
  long_packets?: unknown;
  transitions?: unknown;
  heartbeat_avg?: unknown;
  heartbeat_jitter?: unknown;
  intervals?: unknown;
  has_websocket?: unknown;
  ws_params?: unknown;
  listener_hints?: unknown;
  first_time?: unknown;
  last_time?: unknown;
  packets?: unknown;
  confidence?: unknown;
  summary?: unknown;
}

export interface C2FamilyWireDTO extends Record<string, unknown> {
  candidate_count?: unknown;
  matched_rule_count?: unknown;
  channels?: unknown;
  indicators?: unknown;
  conversations?: unknown;
  beacon_patterns?: unknown;
  host_uri_aggregates?: unknown;
  dns_aggregates?: unknown;
  stream_aggregates?: unknown;
  candidates?: unknown;
  notes?: unknown;
  related_actors?: unknown;
  delivery_chains?: unknown;
  report?: unknown;
}

export interface C2SampleAnalysisWireDTO extends Record<string, unknown> {
  total_matched_packets?: unknown;
  families?: unknown;
  conversations?: unknown;
  cs?: unknown;
  vshell?: unknown;
  notes?: unknown;
}
