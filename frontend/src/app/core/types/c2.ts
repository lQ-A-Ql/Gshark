import type { AnalysisConversation, TrafficBucket } from "./traffic";

export interface C2IndicatorRecord {
  packetId: number;
  streamId?: number;
  time?: string;
  family: "cs" | "vshell";
  channel?: string;
  source?: string;
  destination?: string;
  host?: string;
  uri?: string;
  method?: string;
  indicatorType?: string;
  indicatorValue?: string;
  confidence?: number;
  summary: string;
  evidence?: string;
  tags?: string[];
  actorHints?: string[];
  sampleFamily?: string;
  campaignStage?: string;
  transportTraits?: string[];
  infrastructureHints?: string[];
  ttpTags?: string[];
  attributionConfidence?: number;
}

export interface C2BeaconPattern {
  name: string;
  value: string;
  confidence?: number;
  summary: string;
}

export interface C2ScoreFactor {
  name: string;
  weight: number;
  direction: string;
  summary?: string;
}

export interface C2HTTPEndpointAggregate {
  host: string;
  uri: string;
  channel?: string;
  total: number;
  getCount: number;
  postCount: number;
  methods: TrafficBucket[];
  firstTime?: string;
  lastTime?: string;
  avgInterval?: string;
  jitter?: string;
  intervals?: number[];
  streams?: number[];
  packets?: number[];
  representativePacket?: number;
  confidence?: number;
  signalTags?: string[];
  scoreFactors?: C2ScoreFactor[];
  summary: string;
}

export interface C2DNSAggregate {
  qname: string;
  total: number;
  maxLabelLength: number;
  queryTypes: TrafficBucket[];
  txtCount: number;
  nullCount: number;
  cnameCount: number;
  requestCount: number;
  responseCount: number;
  firstTime?: string;
  lastTime?: string;
  avgInterval?: string;
  jitter?: string;
  intervals?: number[];
  packets?: number[];
  confidence?: number;
  summary: string;
}

export interface C2StreamAggregate {
  streamId: number;
  protocol?: string;
  totalPackets: number;
  archMarkers?: TrafficBucket[];
  lengthPrefixCount: number;
  shortPackets: number;
  longPackets: number;
  transitions: number;
  heartbeatAvg?: string;
  heartbeatJitter?: string;
  intervals?: number[];
  hasWebSocket: boolean;
  wsParams?: string;
  listenerHints?: TrafficBucket[];
  firstTime?: string;
  lastTime?: string;
  packets?: number[];
  confidence?: number;
  summary: string;
}

export interface C2FamilyAnalysis {
  candidateCount: number;
  matchedRuleCount: number;
  channels: TrafficBucket[];
  indicators: TrafficBucket[];
  conversations: AnalysisConversation[];
  beaconPatterns?: C2BeaconPattern[];
  hostUriAggregates?: C2HTTPEndpointAggregate[];
  dnsAggregates?: C2DNSAggregate[];
  streamAggregates?: C2StreamAggregate[];
  candidates: C2IndicatorRecord[];
  notes: string[];
  relatedActors?: TrafficBucket[];
  deliveryChains?: TrafficBucket[];
}

export interface C2SampleAnalysis {
  totalMatchedPackets: number;
  families: TrafficBucket[];
  conversations: AnalysisConversation[];
  cs: C2FamilyAnalysis;
  vshell: C2FamilyAnalysis;
  notes: string[];
}

export interface C2DecryptRequest {
  family: "cs" | "vshell";
  scope?: {
    packetIds?: number[];
    streamIds?: number[];
    useCandidates?: boolean;
    useAggregates?: boolean;
  };
  vshell?: {
    vkey: string;
    salt: string;
    mode?: "auto" | "aes_gcm_md5_salt" | "aes_cbc_md5_salt";
  };
  cs?: {
    keyMode: "aes_hmac" | "aes_rand" | "rsa_private_key";
    aesKey?: string;
    hmacKey?: string;
    aesRand?: string;
    rsaPrivateKey?: string;
    transformMode?: "auto" | "raw" | "base64" | "base64url" | "netbios" | "netbiosu";
  };
}

export interface C2DecryptedRecord {
  packetId?: number;
  streamId?: number;
  time?: string;
  direction?: "client_to_server" | "server_to_client" | "unknown" | string;
  algorithm?: string;
  keyStatus?: "verified" | "unverified" | "not_applicable" | string;
  confidence: number;
  plaintextPreview?: string;
  parsed?: Record<string, unknown>;
  rawLength?: number;
  decryptedLength?: number;
  tags?: string[];
  error?: string;
}

export interface C2DecryptResult {
  family: "cs" | "vshell";
  status: "completed" | "partial" | "failed" | string;
  totalCandidates: number;
  decryptedCount: number;
  failedCount: number;
  records: C2DecryptedRecord[];
  notes: string[];
}
