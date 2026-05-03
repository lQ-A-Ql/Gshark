export interface StreamChunk {
  packetId: number;
  direction: "client" | "server";
  body: string;
}

export interface StreamLoadMeta {
  source?: string;
  loading?: boolean;
  cacheHit?: boolean;
  indexHit?: boolean;
  fileFallback?: boolean;
  tsharkMs?: number;
  overrideCount?: number;
}

export type StreamDecoderKind = "base64" | "behinder" | "antsword" | "godzilla" | "auto";

export interface StreamDecodeResult {
  decoder: StreamDecoderKind;
  summary: string;
  text: string;
  bytesHex: string;
  encoding: string;
  confidence?: number;
  warnings?: string[];
  signals?: string[];
  attemptErrors?: string[];
}

export interface StreamPayloadCandidate {
  id: string;
  label: string;
  kind: string;
  paramName?: string;
  value: string;
  preview?: string;
  confidence?: number;
  decoderHints?: string[];
  fingerprints?: string[];
  familyHint?: string;
  decoderOptionsHint?: Record<string, unknown>;
  sourceRole?: string;
}

export interface StreamPayloadInspection {
  normalizedPayload: string;
  candidates: StreamPayloadCandidate[];
  suggestedCandidateId?: string;
  suggestedDecoder?: StreamDecoderKind | string;
  suggestedFamily?: string;
  confidence?: number;
  reasons?: string[];
}

export interface StreamPayloadSource {
  id: string;
  method?: string;
  host?: string;
  uri?: string;
  packetId: number;
  streamId?: number;
  sourceType?: string;
  paramName?: string;
  payload: string;
  preview?: string;
  confidence?: number;
  signals?: string[];
  decoderHints?: string[];
  familyHint?: string;
  decoderOptionsHint?: Record<string, unknown>;
  sourceRole?: string;
  contentType?: string;
  occurrenceCount?: number;
  firstTime?: string;
  lastTime?: string;
  repeatWindowSeconds?: number;
  relatedPackets?: number[];
  ruleReasons?: string[];
}
