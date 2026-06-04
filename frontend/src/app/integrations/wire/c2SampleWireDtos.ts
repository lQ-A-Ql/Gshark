export interface C2ScoreFactorWireDTO extends Record<string, unknown> {
  name?: string;
  weight?: number;
  direction?: string;
  summary?: string;
}

export interface C2IndicatorRecordWireDTO extends Record<string, unknown> {
  packet_id?: number;
  stream_id?: number;
  time?: string;
  family?: string;
  channel?: string;
  source?: string;
  destination?: string;
  host?: string;
  uri?: string;
  method?: string;
  indicator_type?: string;
  indicator_value?: string;
  confidence?: number;
  summary?: string;
  evidence?: string;
  tags?: string[];
  actor_hints?: string[];
  sample_family?: string;
  campaign_stage?: string;
  transport_traits?: string[];
  infrastructure_hints?: string[];
  ttp_tags?: string[];
  attribution_confidence?: number;
}

export interface C2BeaconPatternWireDTO extends Record<string, unknown> {
  name?: string;
  value?: string;
  confidence?: number;
  summary?: string;
}

export interface C2HTTPEndpointAggregateWireDTO extends Record<string, unknown> {
  host?: string;
  uri?: string;
  channel?: string;
  total?: number;
  get_count?: number;
  post_count?: number;
  methods?: unknown[];
  first_time?: string;
  last_time?: string;
  avg_interval?: string;
  jitter?: string;
  intervals?: number[];
  streams?: number[];
  packets?: number[];
  representative_packet?: number;
  confidence?: number;
  signal_tags?: string[];
  score_factors?: unknown[];
  summary?: string;
}

export interface C2DNSAggregateWireDTO extends Record<string, unknown> {
  qname?: string;
  total?: number;
  max_label_length?: number;
  query_types?: unknown[];
  txt_count?: number;
  null_count?: number;
  cname_count?: number;
  request_count?: number;
  response_count?: number;
  first_time?: string;
  last_time?: string;
  avg_interval?: string;
  jitter?: string;
  intervals?: number[];
  packets?: number[];
  confidence?: number;
  summary?: string;
}

export interface C2StreamAggregateWireDTO extends Record<string, unknown> {
  stream_id?: number;
  protocol?: string;
  total_packets?: number;
  arch_markers?: unknown[];
  length_prefix_count?: number;
  short_packets?: number;
  long_packets?: number;
  transitions?: number;
  heartbeat_avg?: string;
  heartbeat_jitter?: string;
  intervals?: number[];
  has_websocket?: boolean;
  ws_params?: string;
  listener_hints?: unknown[];
  first_time?: string;
  last_time?: string;
  packets?: number[];
  confidence?: number;
  summary?: string;
}

export interface C2FamilyWireDTO extends Record<string, unknown> {
  candidate_count?: number;
  matched_rule_count?: number;
  channels?: unknown[];
  indicators?: unknown[];
  conversations?: unknown[];
  beacon_patterns?: unknown[];
  host_uri_aggregates?: unknown[];
  dns_aggregates?: unknown[];
  stream_aggregates?: unknown[];
  candidates?: unknown[];
  notes?: string[];
  related_actors?: unknown[];
  delivery_chains?: unknown[];
  report?: Record<string, unknown>;
}

export interface C2SampleAnalysisWireDTO extends Record<string, unknown> {
  total_matched_packets?: number;
  families?: unknown[];
  conversations?: unknown[];
  cs?: Record<string, unknown>;
  vshell?: Record<string, unknown>;
  notes?: string[];
}
