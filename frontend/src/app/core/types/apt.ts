import type { TrafficBucket } from "./traffic";

export interface APTScoreFactor {
  name: string;
  weight: number;
  direction: "positive" | "negative" | "missing" | string;
  sourceModule?: string;
  summary?: string;
}

export interface APTEvidenceRecord {
  packetId: number;
  streamId?: number;
  time?: string;
  actorId?: string;
  actorName?: string;
  sourceModule?: string;
  family?: string;
  evidenceType?: string;
  evidenceValue?: string;
  confidence?: number;
  source?: string;
  destination?: string;
  host?: string;
  uri?: string;
  sampleFamily?: string;
  campaignStage?: string;
  transportTraits?: string[];
  infrastructureHints?: string[];
  ttpTags?: string[];
  tags?: string[];
  scoreFactors?: APTScoreFactor[];
  summary: string;
  evidence?: string;
}

export interface APTActorProfile {
  id: string;
  name: string;
  aliases?: string[];
  summary: string;
  confidence?: number;
  evidenceCount: number;
  sampleFamilies: TrafficBucket[];
  campaignStages: TrafficBucket[];
  transportTraits: TrafficBucket[];
  infrastructureHints: TrafficBucket[];
  relatedC2Families: TrafficBucket[];
  ttpTags: TrafficBucket[];
  scoreFactors?: APTScoreFactor[];
  notes: string[];
}

export interface APTAnalysis {
  totalEvidence: number;
  actors: TrafficBucket[];
  sampleFamilies: TrafficBucket[];
  campaignStages: TrafficBucket[];
  transportTraits: TrafficBucket[];
  infrastructureHints: TrafficBucket[];
  relatedC2Families: TrafficBucket[];
  profiles: APTActorProfile[];
  evidence: APTEvidenceRecord[];
  notes: string[];
}
