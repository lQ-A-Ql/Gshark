export type EvidenceModule =
  | "apt"
  | "c2"
  | "hunting"
  | "industrial"
  | "object"
  | "vehicle"
  | "usb"
  | "misc"
  | "stream"
  | "unknown";

export type EvidenceSeverity = "critical" | "high" | "medium" | "low" | "info";

export type EvidenceConfidenceLabel = "high" | "medium" | "low" | "unknown";

export interface UnifiedEvidenceRecord {
  id: string;
  module: EvidenceModule;
  sourceModule?: string;
  packetId?: number;
  streamId?: number;
  family?: string;
  actorId?: string;
  actorName?: string;
  sourceType: string;
  summary: string;
  value?: string;
  confidence?: number;
  confidenceLabel: EvidenceConfidenceLabel;
  severity: EvidenceSeverity;
  source?: string;
  destination?: string;
  host?: string;
  uri?: string;
  tags: string[];
  caveats: string[];
}
