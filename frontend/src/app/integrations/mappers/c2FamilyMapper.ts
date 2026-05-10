import type { C2FamilyAnalysis, C2SampleAnalysis } from "../../core/types";
import { asBucket, asConversation, asStringList } from "./mapperPrimitives";
import { asC2DNSAggregate, asC2HTTPEndpointAggregate, asC2StreamAggregate } from "./c2AggregateMapper";
import { asC2BeaconPattern, asC2Record } from "./c2IndicatorMapper";

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
