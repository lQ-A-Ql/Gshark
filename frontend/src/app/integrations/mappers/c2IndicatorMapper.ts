import type { C2BeaconPattern, C2IndicatorRecord, C2ScoreFactor } from "../../core/types";
import { asStringList } from "./mapperPrimitives";

export function asC2Record(item: any): C2IndicatorRecord {
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

export function asC2BeaconPattern(item: any): C2BeaconPattern {
  return {
    name: String(item.name ?? ""),
    value: String(item.value ?? ""),
    confidence: Number(item.confidence ?? 0) || undefined,
    summary: String(item.summary ?? ""),
  };
}

export function asC2ScoreFactor(item: any): C2ScoreFactor {
  return {
    name: String(item.name ?? ""),
    weight: Number(item.weight ?? 0),
    direction: String(item.direction ?? ""),
    summary: String(item.summary ?? "") || undefined,
  };
}
