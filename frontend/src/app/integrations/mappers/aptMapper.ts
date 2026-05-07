import type { APTAnalysis, APTEvidenceRecord, APTActorProfile, APTScoreFactor } from "../../core/types";
import { asBucket, asStringList } from "./mapperPrimitives";

function asAPTScoreFactor(item: any): APTScoreFactor {
  return {
    name: String(item.name ?? ""),
    weight: Number(item.weight ?? 0),
    direction: String(item.direction ?? ""),
    sourceModule: String(item.source_module ?? "") || undefined,
    summary: String(item.summary ?? "") || undefined,
  };
}

function asAPTRecord(item: any): APTEvidenceRecord {
  return {
    packetId: Number(item.packet_id ?? 0),
    streamId: Number(item.stream_id ?? 0) || undefined,
    time: String(item.time ?? "") || undefined,
    actorId: String(item.actor_id ?? "") || undefined,
    actorName: String(item.actor_name ?? "") || undefined,
    sourceModule: String(item.source_module ?? "") || undefined,
    family: String(item.family ?? "") || undefined,
    evidenceType: String(item.evidence_type ?? "") || undefined,
    evidenceValue: String(item.evidence_value ?? "") || undefined,
    confidence: Number(item.confidence ?? 0) || undefined,
    source: String(item.source ?? "") || undefined,
    destination: String(item.destination ?? "") || undefined,
    host: String(item.host ?? "") || undefined,
    uri: String(item.uri ?? "") || undefined,
    sampleFamily: String(item.sample_family ?? "") || undefined,
    campaignStage: String(item.campaign_stage ?? "") || undefined,
    transportTraits: asStringList(item.transport_traits),
    infrastructureHints: asStringList(item.infrastructure_hints),
    ttpTags: asStringList(item.ttp_tags),
    tags: asStringList(item.tags),
    scoreFactors: Array.isArray(item.score_factors) ? item.score_factors.map(asAPTScoreFactor) : [],
    summary: String(item.summary ?? ""),
    evidence: String(item.evidence ?? "") || undefined,
  };
}

function asAPTProfile(item: any): APTActorProfile {
  return {
    id: String(item.id ?? ""),
    name: String(item.name ?? ""),
    aliases: asStringList(item.aliases),
    summary: String(item.summary ?? ""),
    confidence: Number(item.confidence ?? 0) || undefined,
    evidenceCount: Number(item.evidence_count ?? 0),
    sampleFamilies: Array.isArray(item.sample_families) ? item.sample_families.map(asBucket) : [],
    campaignStages: Array.isArray(item.campaign_stages) ? item.campaign_stages.map(asBucket) : [],
    transportTraits: Array.isArray(item.transport_traits) ? item.transport_traits.map(asBucket) : [],
    infrastructureHints: Array.isArray(item.infrastructure_hints) ? item.infrastructure_hints.map(asBucket) : [],
    relatedC2Families: Array.isArray(item.related_c2_families) ? item.related_c2_families.map(asBucket) : [],
    ttpTags: Array.isArray(item.ttp_tags) ? item.ttp_tags.map(asBucket) : [],
    scoreFactors: Array.isArray(item.score_factors) ? item.score_factors.map(asAPTScoreFactor) : [],
    notes: asStringList(item.notes),
  };
}

export function asAPTAnalysis(payload: any): APTAnalysis {
  return {
    totalEvidence: Number(payload?.total_evidence ?? 0),
    actors: Array.isArray(payload?.actors) ? payload.actors.map(asBucket) : [],
    sampleFamilies: Array.isArray(payload?.sample_families) ? payload.sample_families.map(asBucket) : [],
    campaignStages: Array.isArray(payload?.campaign_stages) ? payload.campaign_stages.map(asBucket) : [],
    transportTraits: Array.isArray(payload?.transport_traits) ? payload.transport_traits.map(asBucket) : [],
    infrastructureHints: Array.isArray(payload?.infrastructure_hints) ? payload.infrastructure_hints.map(asBucket) : [],
    relatedC2Families: Array.isArray(payload?.related_c2_families) ? payload.related_c2_families.map(asBucket) : [],
    profiles: Array.isArray(payload?.profiles) ? payload.profiles.map(asAPTProfile) : [],
    evidence: Array.isArray(payload?.evidence) ? payload.evidence.map(asAPTRecord) : [],
    notes: asStringList(payload?.notes),
  };
}
