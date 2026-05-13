import type { C2FamilyAnalysis, C2SampleAnalysis } from "../../core/types";
import { asInvestigationReport } from "./investigationReportMapper";
import { asArray, asBucket, asConversation, asPlainObject, asStringList } from "./mapperPrimitives";
import { asC2DNSAggregate, asC2HTTPEndpointAggregate, asC2StreamAggregate } from "./c2AggregateMapper";
import { asC2BeaconPattern, asC2Record } from "./c2IndicatorMapper";

export function asC2SampleAnalysis(input: unknown): C2SampleAnalysis {
  const payload = asPlainObject(input);
  return {
    totalMatchedPackets: Number(payload?.total_matched_packets ?? 0),
    families: asArray(payload?.families).map(asBucket),
    conversations: asArray(payload?.conversations).map(asConversation),
    cs: asC2Family(payload?.cs ?? {}),
    vshell: asC2Family(payload?.vshell ?? {}),
    notes: asStringList(payload?.notes),
  };
}

function asC2Family(input: unknown): C2FamilyAnalysis {
  const item = asPlainObject(input);
  return {
    candidateCount: Number(item?.candidate_count ?? 0),
    matchedRuleCount: Number(item?.matched_rule_count ?? 0),
    channels: asArray(item?.channels).map(asBucket),
    indicators: asArray(item?.indicators).map(asBucket),
    conversations: asArray(item?.conversations).map(asConversation),
    beaconPatterns: asArray(item?.beacon_patterns).map(asC2BeaconPattern),
    hostUriAggregates: asArray(item?.host_uri_aggregates).map(asC2HTTPEndpointAggregate),
    dnsAggregates: asArray(item?.dns_aggregates).map(asC2DNSAggregate),
    streamAggregates: asArray(item?.stream_aggregates).map(asC2StreamAggregate),
    candidates: asArray(item?.candidates).map(asC2Record),
    notes: asStringList(item?.notes),
    relatedActors: asArray(item?.related_actors).map(asBucket),
    deliveryChains: asArray(item?.delivery_chains).map(asBucket),
    report: asInvestigationReport(item?.report),
  };
}
