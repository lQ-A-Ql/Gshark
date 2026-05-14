import type { APTAnalysis, APTEvidenceRecord, APTActorProfile, APTScoreFactor } from "../../core/types";
import type {
  APTActorProfileWireDTO,
  APTAnalysisWireDTO,
  APTEvidenceRecordWireDTO,
  APTScoreFactorWireDTO,
} from "../wire/aptWireDtos";
import { asArray, asBucket, asPlainObject, asStringList } from "./mapperPrimitives";

function asAPTScoreFactor(input: unknown): APTScoreFactor {
  const item = asPlainObject(input) as APTScoreFactorWireDTO | undefined;
  return {
    name: String(item?.name ?? ""),
    weight: Number(item?.weight ?? 0),
    direction: String(item?.direction ?? ""),
    sourceModule: String(item?.source_module ?? "") || undefined,
    summary: String(item?.summary ?? "") || undefined,
  };
}

function asAPTRecord(input: unknown): APTEvidenceRecord {
  const item = asPlainObject(input) as APTEvidenceRecordWireDTO | undefined;
  return {
    packetId: Number(item?.packet_id ?? 0),
    streamId: Number(item?.stream_id ?? 0) || undefined,
    time: String(item?.time ?? "") || undefined,
    actorId: String(item?.actor_id ?? "") || undefined,
    actorName: String(item?.actor_name ?? "") || undefined,
    sourceModule: String(item?.source_module ?? "") || undefined,
    family: String(item?.family ?? "") || undefined,
    evidenceType: String(item?.evidence_type ?? "") || undefined,
    evidenceValue: String(item?.evidence_value ?? "") || undefined,
    confidence: Number(item?.confidence ?? 0) || undefined,
    source: String(item?.source ?? "") || undefined,
    destination: String(item?.destination ?? "") || undefined,
    host: String(item?.host ?? "") || undefined,
    uri: String(item?.uri ?? "") || undefined,
    sampleFamily: String(item?.sample_family ?? "") || undefined,
    campaignStage: String(item?.campaign_stage ?? "") || undefined,
    transportTraits: asStringList(item?.transport_traits),
    infrastructureHints: asStringList(item?.infrastructure_hints),
    ttpTags: asStringList(item?.ttp_tags),
    tags: asStringList(item?.tags),
    scoreFactors: asArray(item?.score_factors).map(asAPTScoreFactor),
    summary: String(item?.summary ?? ""),
    evidence: String(item?.evidence ?? "") || undefined,
  };
}

function asAPTProfile(input: unknown): APTActorProfile {
  const item = asPlainObject(input) as APTActorProfileWireDTO | undefined;
  return {
    id: String(item?.id ?? ""),
    name: String(item?.name ?? ""),
    aliases: asStringList(item?.aliases),
    summary: String(item?.summary ?? ""),
    confidence: Number(item?.confidence ?? 0) || undefined,
    evidenceCount: Number(item?.evidence_count ?? 0),
    sampleFamilies: asArray(item?.sample_families).map(asBucket),
    campaignStages: asArray(item?.campaign_stages).map(asBucket),
    transportTraits: asArray(item?.transport_traits).map(asBucket),
    infrastructureHints: asArray(item?.infrastructure_hints).map(asBucket),
    relatedC2Families: asArray(item?.related_c2_families).map(asBucket),
    ttpTags: asArray(item?.ttp_tags).map(asBucket),
    scoreFactors: asArray(item?.score_factors).map(asAPTScoreFactor),
    notes: asStringList(item?.notes),
  };
}

export function asAPTAnalysis(input: unknown): APTAnalysis {
  const payload = asPlainObject(input) as APTAnalysisWireDTO | undefined;
  return {
    totalEvidence: Number(payload?.total_evidence ?? 0),
    actors: asArray(payload?.actors).map(asBucket),
    sampleFamilies: asArray(payload?.sample_families).map(asBucket),
    campaignStages: asArray(payload?.campaign_stages).map(asBucket),
    transportTraits: asArray(payload?.transport_traits).map(asBucket),
    infrastructureHints: asArray(payload?.infrastructure_hints).map(asBucket),
    relatedC2Families: asArray(payload?.related_c2_families).map(asBucket),
    profiles: asArray(payload?.profiles).map(asAPTProfile),
    evidence: asArray(payload?.evidence).map(asAPTRecord),
    notes: asStringList(payload?.notes),
  };
}
