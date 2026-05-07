import type {
  C2BeaconPattern,
  C2DNSAggregate,
  C2FamilyAnalysis,
  C2HTTPEndpointAggregate,
  C2IndicatorRecord,
  C2SampleAnalysis,
  C2ScoreFactor,
  C2StreamAggregate,
} from "../../core/types";
import { asBucket, asConversation, asPositiveFiniteNumbers, asPositiveNumbers, asStringList } from "./mapperPrimitives";

function asC2Record(item: any): C2IndicatorRecord {
  return {
    packetId: Number(item.packet_id ?? 0),
    streamId: Number(item.stream_id ?? 0) || undefined,
    time: String(item.time ?? "") || undefined,
    family: String(item.family ?? "cs") === "vshell" ? "vshell" : "cs",
    channel: String(item.channel ?? "") || undefined,
    source: String(item.source ?? "") || undefined,
    destination: String(item.destination ?? "") || undefined,
    host: String(item.host ?? "") || undefined,
    uri: String(item.uri ?? "") || undefined,
    method: String(item.method ?? "") || undefined,
    indicatorType: String(item.indicator_type ?? "") || undefined,
    indicatorValue: String(item.indicator_value ?? "") || undefined,
    confidence: Number(item.confidence ?? 0) || undefined,
    summary: String(item.summary ?? ""),
    evidence: String(item.evidence ?? "") || undefined,
    tags: asStringList(item.tags),
    actorHints: asStringList(item.actor_hints),
    sampleFamily: String(item.sample_family ?? "") || undefined,
    campaignStage: String(item.campaign_stage ?? "") || undefined,
    transportTraits: asStringList(item.transport_traits),
    infrastructureHints: asStringList(item.infrastructure_hints),
    ttpTags: asStringList(item.ttp_tags),
    attributionConfidence: Number(item.attribution_confidence ?? 0) || undefined,
  };
}

function asC2BeaconPattern(item: any): C2BeaconPattern {
  return {
    name: String(item.name ?? ""),
    value: String(item.value ?? ""),
    confidence: Number(item.confidence ?? 0) || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asC2ScoreFactor(item: any): C2ScoreFactor {
  return {
    name: String(item.name ?? ""),
    weight: Number(item.weight ?? 0),
    direction: String(item.direction ?? ""),
    summary: String(item.summary ?? "") || undefined,
  };
}

function asC2HTTPEndpointAggregate(item: any): C2HTTPEndpointAggregate {
  return {
    host: String(item.host ?? ""),
    uri: String(item.uri ?? ""),
    channel: String(item.channel ?? "") || undefined,
    total: Number(item.total ?? 0),
    getCount: Number(item.get_count ?? 0),
    postCount: Number(item.post_count ?? 0),
    methods: Array.isArray(item.methods) ? item.methods.map(asBucket) : [],
    firstTime: String(item.first_time ?? "") || undefined,
    lastTime: String(item.last_time ?? "") || undefined,
    avgInterval: String(item.avg_interval ?? "") || undefined,
    jitter: String(item.jitter ?? "") || undefined,
    intervals: asPositiveFiniteNumbers(item.intervals),
    streams: asPositiveNumbers(item.streams),
    packets: asPositiveNumbers(item.packets),
    representativePacket: Number(item.representative_packet ?? 0) || undefined,
    confidence: Number(item.confidence ?? 0) || undefined,
    signalTags: asStringList(item.signal_tags),
    scoreFactors: Array.isArray(item.score_factors) ? item.score_factors.map(asC2ScoreFactor) : [],
    summary: String(item.summary ?? ""),
  };
}

function asC2DNSAggregate(item: any): C2DNSAggregate {
  return {
    qname: String(item.qname ?? ""),
    total: Number(item.total ?? 0),
    maxLabelLength: Number(item.max_label_length ?? 0),
    queryTypes: Array.isArray(item.query_types) ? item.query_types.map(asBucket) : [],
    txtCount: Number(item.txt_count ?? 0),
    nullCount: Number(item.null_count ?? 0),
    cnameCount: Number(item.cname_count ?? 0),
    requestCount: Number(item.request_count ?? 0),
    responseCount: Number(item.response_count ?? 0),
    firstTime: String(item.first_time ?? "") || undefined,
    lastTime: String(item.last_time ?? "") || undefined,
    avgInterval: String(item.avg_interval ?? "") || undefined,
    jitter: String(item.jitter ?? "") || undefined,
    intervals: asPositiveFiniteNumbers(item.intervals),
    packets: asPositiveNumbers(item.packets),
    confidence: Number(item.confidence ?? 0) || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asC2StreamAggregate(item: any): C2StreamAggregate {
  return {
    streamId: Number(item.stream_id ?? 0),
    protocol: String(item.protocol ?? "") || undefined,
    totalPackets: Number(item.total_packets ?? 0),
    archMarkers: Array.isArray(item.arch_markers) ? item.arch_markers.map(asBucket) : [],
    lengthPrefixCount: Number(item.length_prefix_count ?? 0),
    shortPackets: Number(item.short_packets ?? 0),
    longPackets: Number(item.long_packets ?? 0),
    transitions: Number(item.transitions ?? 0),
    heartbeatAvg: String(item.heartbeat_avg ?? "") || undefined,
    heartbeatJitter: String(item.heartbeat_jitter ?? "") || undefined,
    intervals: asPositiveFiniteNumbers(item.intervals),
    hasWebSocket: Boolean(item.has_websocket),
    wsParams: String(item.ws_params ?? "") || undefined,
    listenerHints: Array.isArray(item.listener_hints) ? item.listener_hints.map(asBucket) : [],
    firstTime: String(item.first_time ?? "") || undefined,
    lastTime: String(item.last_time ?? "") || undefined,
    packets: asPositiveNumbers(item.packets),
    confidence: Number(item.confidence ?? 0) || undefined,
    summary: String(item.summary ?? ""),
  };
}

function asC2Family(item: any): C2FamilyAnalysis {
  return {
    candidateCount: Number(item.candidate_count ?? 0),
    matchedRuleCount: Number(item.matched_rule_count ?? 0),
    channels: Array.isArray(item.channels) ? item.channels.map(asBucket) : [],
    indicators: Array.isArray(item.indicators) ? item.indicators.map(asBucket) : [],
    conversations: Array.isArray(item.conversations) ? item.conversations.map(asConversation) : [],
    beaconPatterns: Array.isArray(item.beacon_patterns) ? item.beacon_patterns.map(asC2BeaconPattern) : [],
    hostUriAggregates: Array.isArray(item.host_uri_aggregates)
      ? item.host_uri_aggregates.map(asC2HTTPEndpointAggregate)
      : [],
    dnsAggregates: Array.isArray(item.dns_aggregates) ? item.dns_aggregates.map(asC2DNSAggregate) : [],
    streamAggregates: Array.isArray(item.stream_aggregates) ? item.stream_aggregates.map(asC2StreamAggregate) : [],
    candidates: Array.isArray(item.candidates) ? item.candidates.map(asC2Record) : [],
    notes: asStringList(item.notes),
    relatedActors: Array.isArray(item.related_actors) ? item.related_actors.map(asBucket) : [],
    deliveryChains: Array.isArray(item.delivery_chains) ? item.delivery_chains.map(asBucket) : [],
  };
}

export function asC2SampleAnalysis(payload: any): C2SampleAnalysis {
  return {
    totalMatchedPackets: Number(payload?.total_matched_packets ?? 0),
    families: Array.isArray(payload?.families) ? payload.families.map(asBucket) : [],
    conversations: Array.isArray(payload?.conversations) ? payload.conversations.map(asConversation) : [],
    cs: asC2Family(payload?.cs ?? {}),
    vshell: asC2Family(payload?.vshell ?? {}),
    notes: asStringList(payload?.notes),
  };
}
